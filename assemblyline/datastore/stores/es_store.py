
import elasticsearch
import elasticsearch.helpers
import json
import logging
import time

from copy import deepcopy

from assemblyline import odm
from assemblyline.datastore import Collection, BaseStore, log
from assemblyline.datastore.exceptions import SearchException, SearchRetryException
from assemblyline.datastore.support.elasticsearch.schemas import default_index, default_mapping, \
    default_dynamic_templates
from assemblyline.datastore.support.elasticsearch.build import build_mapping, back_mapping


def _strip_lists(model, data):
    """Elasticsearch returns everything as lists, regardless of whether
    we want the field to be multi-valued or not. This method uses the model's
    knowlage of what should or should not have multiple values to fix the data.
    """
    fields = model.fields()
    out = {}
    for key, value in odm.flat_to_nested(data).items():
        doc_type = fields.get(key, fields.get('', model))
        if isinstance(doc_type, odm.List):
            out[key] = value
        elif isinstance(doc_type, odm.Compound) or isinstance(doc_type, odm.Mapping):
            out[key] = _strip_lists(doc_type.child_type, value)
        elif isinstance(value, list):
            out[key] = value[0]
        else:
            out[key] = value
    return out


def parse_sort(sort):
    """
    This function tries to do two things at once:
        - convert solr sort syntax to elastic,
        - convert any sorts on the key _id to _id_
    """
    if isinstance(sort, list):
        return [parse_sort(row) for row in sort]
    elif isinstance(sort, dict):
        return {('id' if key == '_id' else key): value for key, value in sort.items()}

    parts = sort.split(' ')
    if len(parts) == 1:
        if parts == '_id':
            return ['id']
        return [parts]
    elif len(parts) == 2:
        if parts[1] not in ['asc', 'desc']:
            raise SearchException('Unknown sort parameter ' + sort)
        if parts[0] == '_id':
            return [{'id': parts[1]}]
        return [{parts[0]: parts[1]}]
    raise SearchException('Unknown sort parameter ' + sort)


class RetryableIterator(object):
    def __init__(self, collection, iterable):
        self._iter = iter(iterable)
        self.collection = collection

    def __iter__(self):
        return self

    def __next__(self):
        return self.collection.with_retries(self._iter.__next__)


class ESCollection(Collection):
    DEFAULT_SORT = [{'_id': 'asc'}]
    MAX_SEARCH_ROWS = 500
    MAX_GROUP_LIMIT = 10
    MAX_FACET_LIMIT = 100
    DEFAULT_SEARCH_VALUES = {
        'timeout': None,
        'field_list': None,
        'facet_active': False,
        'facet_mincount': 1,
        'facet_fields': [],
        'stats_active': False,
        'stats_fields': [],
        'filters': [],
        'group_active': False,
        'group_field': None,
        'group_sort': None,
        'group_limit': 1,
        'histogram_active': False,
        'histogram_field': None,
        'histogram_type': None,
        'histogram_gap': None,
        'histogram_mincount': 1,
        'start': 0,
        'rows': Collection.DEFAULT_ROW_SIZE,
        'query': "*",
        'sort': DEFAULT_SORT,
        'df': None
    }

    def __init__(self, datastore, name, model_class=None, replicas=0, shards=1):
        self.replicas = replicas
        self.shards = shards

        super().__init__(datastore, name, model_class=model_class)

        self.stored_fields = {}
        if model_class:
            for name, field in model_class.flat_fields().items():
                if field.store:
                    self.stored_fields[name] = field

    def with_retries(self, func, *args, **kwargs):
        retries = 0
        updated = 0
        deleted = 0
        while True:
            try:
                ret_val = func(*args, **kwargs)

                if retries:
                    log.info('Reconnected to elasticsearch!')

                if updated:
                    ret_val['updated'] += updated

                if deleted:
                    ret_val['deleted'] += deleted

                return ret_val

            except elasticsearch.exceptions.NotFoundError as e:
                if "index_not_found_exception" in str(e):
                    time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                    log.warning("The index does not exist. Trying to recreate it...")
                    self._ensure_collection()
                    self.datastore.connection_reset()
                    retries += 1
                else:
                    raise

            except elasticsearch.exceptions.ConflictError as ce:
                updated += ce.info.get('updated', 0)
                deleted += ce.info.get('deleted', 0)

                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.datastore.connection_reset()
                retries += 1

            except (SearchRetryException,
                    elasticsearch.exceptions.ConnectionError,
                    elasticsearch.exceptions.ConnectionTimeout) as e:
                if not isinstance(e, SearchRetryException):
                    log.warning("No connection to elasticsearch, retying...")
                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.datastore.connection_reset()
                retries += 1

            except elasticsearch.exceptions.TransportError as e:
                err_code, msg, cause = e.args
                if err_code == 503 or err_code == '503':
                    log.warning("Looks like index is not ready yet, retying...")
                    time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                    self.datastore.connection_reset()
                    retries += 1
                else:
                    raise

    def commit(self):
        self.with_retries(self.datastore.client.indices.refresh, self.name)
        self.with_retries(self.datastore.client.indices.clear_cache, self.name)
        return True

    def multiget(self, key_list, as_dictionary=True, as_obj=True):
        if as_dictionary:
            out = {}
        else:
            out = []

        if key_list:
            data = self.with_retries(self.datastore.client.mget, {'ids': key_list}, index=self.name, doc_type='_doc')
            for row in data.get('docs', []):
                if 'found' in row and not row['found']:
                    raise KeyError(row['_id'])
                if '__non_doc_raw__' in row['_source']:
                    if as_dictionary:
                        out[row['_id']] = row['_source']['__non_doc_raw__']
                    else:
                        out.append(row['_source']['__non_doc_raw__'])
                else:
                    row['_source'].pop('id', None)
                    if as_dictionary:
                        out[row['_id']] = self.normalize(row['_source'], as_obj=as_obj)
                    else:
                        out.append(self.normalize(row['_source'], as_obj=as_obj))
        return out

    def _get(self, key, retries):
        if retries is None:
            retries = self.RETRY_NONE

        done = False
        while not done:

            try:
                data = self.with_retries(self.datastore.client.get, index=self.name,
                                         doc_type='_doc', id=key)['_source']
                # TODO: Maybe we should not allow data that is not a dictionary...
                if "__non_doc_raw__" in data:
                    return data['__non_doc_raw__']
                data.pop('id', None)
                return data
            except elasticsearch.exceptions.NotFoundError:
                if retries > 0:
                    time.sleep(0.05)
                    retries -= 1
                elif retries < 0:
                    time.sleep(0.05)
                else:
                    done = True

        return None

    def _save(self, key, data):
        if self.model_class:
            saved_data = data.as_primitives(hidden_fields=True)
        else:
            if not isinstance(data, dict):
                saved_data = {'__non_doc_raw__': data}
            else:
                saved_data = deepcopy(data)

        saved_data['id'] = key

        self.with_retries(
            self.datastore.client.index,
            index=self.name,
            doc_type='_doc',
            id=key,
            body=json.dumps(saved_data)
        )

        return True

    def delete(self, key):
        try:
            info = self.with_retries(self.datastore.client.delete, id=key, doc_type='_doc', index=self.name)
            return info['result'] == 'deleted'
        except elasticsearch.NotFoundError:
            return True

    def delete_matching(self, query, workers=20):
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": query
                        }
                    }
                }
            }
        }
        try:
            info = self.with_retries(self.datastore.client.delete_by_query, index=self.name,
                                     body=query_body, doc_type='_doc')
            return info.get('deleted', 0) != 0
        except elasticsearch.NotFoundError:
            return False

    def _create_scripts_from_operations(self, operations):
        op_sources = []
        op_params = {}
        val_id = 0
        for op, doc_key, value in operations:
            if op == self.UPDATE_SET:
                op_sources.append(f"ctx._source.{doc_key} = params.value{val_id}")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_APPEND:
                op_sources.append(f"ctx._source.{doc_key}.add(params.value{val_id})")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_REMOVE:
                op_sources.append(f"ctx._source.{doc_key}.remove(ctx._source.{doc_key}.indexOf(params.value{val_id}))")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_INC:
                op_sources.append(f"ctx._source.{doc_key} += params.value{val_id}")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_DEC:
                op_sources.append(f"ctx._source.{doc_key} -= params.value{val_id}")
                op_params[f'value{val_id}'] = value

            val_id += 1

        script = {
            "lang": "painless",
            "source": """;\n""".join(op_sources),
            "params": op_params
        }
        return script

    def _update(self, key, operations):
        script = self._create_scripts_from_operations(operations)

        update_body = {
            "script": script
        }

        # noinspection PyBroadException
        try:
            res = self.with_retries(self.datastore.client.update, index=self.name,
                                    doc_type='_doc', id=key, body=update_body)
        except Exception:
            return False

        return res['result'] == "updated"

    def _update_by_query(self, query, operations, filters):
        if filters is None:
            filters = []

        script = self._create_scripts_from_operations(operations)

        query_body = {
            "script": script,
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": query
                        }
                    },
                    'filter': [{'query_string': {'query': ff}} for ff in filters]
                }
            }
        }

        # noinspection PyBroadException
        try:
            res = self.with_retries(self.datastore.client.update_by_query, index=self.name,
                                    doc_type='_doc', body=query_body)
        except Exception:
            return False

        return res['updated']

    def _format_output(self, result, fields=None, as_obj=True):
        # Getting search document data
        source = result.get('fields', {})
        source_data = result.pop('_source', None)
        item_id = result['_id']

        # Remove extra fields that should not show up in the search results
        source.pop('_version', None)
        source.pop(self.DEFAULT_SEARCH_FIELD, None)
        source.pop('id', None)

        if self.model_class:
            if not fields or '*' in fields:
                fields = list(self.stored_fields.keys())
                fields.append('id')
            elif isinstance(fields, str):
                fields = fields.split(',')

            if source_data:
                source_data.pop('id', None)
                return self.model_class(source_data, docid=item_id)

            source = _strip_lists(self.model_class, source)
            if as_obj:
                return self.model_class(source, mask=fields, docid=item_id)
            else:
                if 'id' in fields:
                    source['id'] = item_id

                return source

        if isinstance(fields, str):
            fields = fields

        if fields is None or '*' in fields or 'id' in fields:
            source['id'] = [item_id]

        if fields is None or '*' in fields:
            return source

        return {key: val for key, val in source.items() if key in fields}

    def _search(self, args=None):
        parsed_values = deepcopy(self.DEFAULT_SEARCH_VALUES)

        # TODO: we should validate values for max rows, group length, history length...
        for key, value in args:
            if key not in parsed_values:
                all_args = '; '.join('%s=%s' % (field_name, field_value) for field_name, field_value in args)
                raise ValueError("Unknown query argument: %s %s of [%s]" % (key, value, all_args))

            parsed_values[key] = value

        # This is our minimal query, the following sections will fill it out
        # with whatever extra options the search has been given.
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": parsed_values['query']
                        }
                    },
                    'filter': [{'query_string': {'query': ff}} for ff in parsed_values['filters']]
                }
            },
            'from': parsed_values['start'],
            'size': parsed_values['rows'],
            'sort': parse_sort(parsed_values['sort']),
            "stored_fields": parsed_values['field_list'] or ['*']
        }

        if parsed_values['df']:
            query_body["query"]["bool"]["must"]["query_string"]["default_field"] = parsed_values['df']

        # Time limit for the query
        if parsed_values['timeout']:
            query_body['timeout'] = parsed_values['timeout']

        # Add an histogram aggregation
        # TODO: Should we turn off normal queries when histogram is active?
        if parsed_values['histogram_active']:
            query_body["aggregations"] = query_body.get("aggregations", {})
            query_body["aggregations"]["histogram"] = {
                parsed_values['histogram_type']: {
                    "field": parsed_values['histogram_field'],
                    "interval": parsed_values['histogram_gap'],
                    "min_doc_count": parsed_values['histogram_mincount']
                }
            }

        # Add a facet aggregation
        # TODO: Should we turn off normal queries when facet is active?
        if parsed_values['facet_active']:
            query_body["aggregations"] = query_body.get("aggregations", {})
            for field in parsed_values['facet_fields']:
                query_body["aggregations"][field] = {
                    "terms": {
                        "field": field,
                        "min_doc_count": parsed_values['facet_mincount']
                    }
                }

        # Add a facet aggregation
        # TODO: Should we turn off normal queries when facet is active?
        if parsed_values['stats_active']:
            query_body["aggregations"] = query_body.get("aggregations", {})
            for field in parsed_values['stats_fields']:
                query_body["aggregations"][f"{field}_stats"] = {
                    "stats": {
                        "field": field
                    }
                }

        # Add a group aggregation
        if parsed_values['group_active']:
            query_body["collapse"] = {
                "field": parsed_values['group_field'],
                "inner_hits": {
                    "name": "group",
                    "stored_fields": parsed_values['field_list'] or ['*'],
                    "size": parsed_values['group_limit'],
                    "sort": parse_sort(parsed_values['group_sort']) or [{parsed_values['group_field']: 'asc'}]
                }
            }

        try:
            # Run the query
            result = self.with_retries(self.datastore.client.search, index=self.name, body=json.dumps(query_body))
            return result

        except (elasticsearch.TransportError, elasticsearch.RequestError) as e:
            try:
                err_msg = e.info['error']['root_cause'][0]['reason']
            except (ValueError, KeyError, IndexError):
                err_msg = str(e)
            raise SearchException(err_msg)

        except (elasticsearch.ConnectionError, elasticsearch.ConnectionTimeout) as error:
            raise SearchRetryException("collection: %s, query: %s, error: %s" % (self.name, query_body, str(error)))

        except Exception as error:
            raise SearchException("collection: %s, query: %s, error: %s" % (self.name, query_body, str(error)))

    def search(self, query, offset=0, rows=None, sort=None,
               fl=None, timeout=None, filters=None, access_control=None, as_obj=True):

        if rows is None:
            rows = self.DEFAULT_ROW_SIZE

        if sort is None:
            sort = self.DEFAULT_SORT

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        if access_control:
            filters.append(access_control)

        args = [
            ('query', query),
            ('start', offset),
            ('rows', rows),
            ('sort', sort),
            ('df', self.DEFAULT_SEARCH_FIELD)
        ]

        if fl:
            field_list = fl.split(',')
            args.append(('field_list', field_list))
        else:
            field_list = None

        if timeout:
            args.append(('timeout', "%sms" % timeout))

        if filters:
            args.append(('filters', filters))

        result = self._search(args)

        return {
            "offset": int(offset),
            "rows": int(rows),
            "total": int(result['hits']['total']['value']),
            "items": [self._format_output(doc, field_list, as_obj=as_obj) for doc in result['hits']['hits']]
        }

    def stream_search(self, query, fl=None, filters=None, access_control=None, item_buffer_size=200, as_obj=True):
        if item_buffer_size > 500 or item_buffer_size < 50:
            raise SearchException("Variable item_buffer_size must be between 50 and 500.")

        if query in ["*", "*:*"] and fl != 'id':
            raise SearchException("You did not specified a query, you just asked for everything... Play nice.")

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        if access_control:
            filters.append(access_control)

        if fl:
            fl = fl.split(',')

        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "default_field": 'id',
                            "query": query
                        }
                    },
                    'filter': [{'query_string': {'query': ff}} for ff in filters]
                }
            },
            "sort": parse_sort(self.datastore.DEFAULT_SORT),
            "stored_fields": fl or ['*']
        }

        iterator = RetryableIterator(
            self,
            elasticsearch.helpers.scan(
            self.datastore.client,
            query=query_body,
            index=self.name,
            doc_type='_doc',
            preserve_order=True)
        )

        for value in iterator:
            # Unpack the results, ensure the id is always set
            yield self._format_output(value, fl, as_obj=as_obj)

    def histogram(self, field, start, end, gap, query="id:*", mincount=1, filters=None, access_control=None):
        type_modifier = self._validate_steps_count(start, end, gap)
        start = type_modifier(start)
        end = type_modifier(end)
        gap = type_modifier(gap)

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]
        filters.append('{field}:[{min} TO {max}]'.format(field=field, min=start, max=end))

        args = [
            ('query', query),
            ('histogram_active', True),
            ('histogram_field', field),
            ('histogram_type', "date_histogram" if isinstance(gap, str) else 'histogram'),
            ('histogram_gap', gap.strip('+') if isinstance(gap, str) else gap),
            ('histogram_mincount', mincount)
        ]

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args)

        # Convert the histogram into a dictionary
        return {type_modifier(row.get('key_as_string', row['key'])): row['doc_count']
                for row in result['aggregations']['histogram']['buckets']}

    def facet(self, field, query="id:*", prefix=None, contains=None, ignore_case=False, sort=None, limit=10,
              mincount=1, filters=None, access_control=None):
        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('facet_active', True),
            ('facet_fields', [field]),
            ('facet_mincount', mincount),
            ('rows', 0)
        ]

        # TODO: prefix, contains, ignore_case, sort

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args)

        # Convert the histogram into a dictionary
        return {row.get('key_as_string', row['key']): row['doc_count']
                for row in result['aggregations'][field]['buckets']}

    def stats(self, field, query="id:*", filters=None, access_control=None):
        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('stats_active', True),
            ('stats_fields', [field]),
            ('rows', 0)
        ]

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args)
        return result['aggregations'][f"{field}_stats"]

    def grouped_search(self, group_field, query="id:*", offset=0, sort=None, group_sort=None, fl=None, limit=1,
                       rows=None, filters=None, access_control=None, as_obj=True):

        if rows is None:
            rows = self.DEFAULT_ROW_SIZE

        if sort is None:
            sort = self.DEFAULT_SORT

        if group_sort is None:
            group_sort = self.DEFAULT_SORT

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('group_active', True),
            ('group_field', group_field),
            ('group_limit', limit),
            ('group_sort', group_sort),
            ('start', offset),
            ('rows', rows),
            ('sort', sort)
        ]

        filters.append("%s:*" % group_field)

        if fl:
            field_list = fl.split(',')
            args.append(('field_list', field_list))
        else:
            field_list = None

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args)

        return {
            'offset': offset,
            'rows': rows,
            'total': int(result['hits']['total']['value']),
            'items': [{
                'value': collapsed['fields'][group_field][0],
                'total': int(collapsed['inner_hits']['group']['hits']['total']['value']),
                'items': [self._format_output(row, field_list, as_obj=as_obj)
                          for row in collapsed['inner_hits']['group']['hits']['hits']]
            } for collapsed in result['hits']['hits']]
        }

    @staticmethod
    def _get_odm_type(ds_type):
        try:
            return back_mapping[ds_type].__name__.lower()
        except KeyError:
            return ds_type.lower()

    def fields(self):
        # TODO: map fields using the model so they are consistent throughout all datastores?

        def flatten_fields(props):
            out = {}
            for name, value in props.items():
                if 'properties' in value:
                    for child, cprops in flatten_fields(value['properties']).items():
                        out[name + '.' + child] = cprops
                elif 'type' in value:
                    out[name] = value
                else:
                    raise ValueError("Unknown field data " + str(props))
            return out

        data = self.with_retries(self.datastore.client.indices.get, self.name)

        properties = flatten_fields(data[self.name]['mappings'].get('properties', {}))
        if self.model_class:
            model_fields = self.model_class.flat_fields()
        else:
            model_fields = {}

        collection_data = {}

        for p_name, p_val in properties.items():
            if p_name.startswith("_") or "//" in p_name:
                continue
            if not Collection.FIELD_SANITIZER.match(p_name):
                continue

            field_model = model_fields.get(p_name, None)
            f_type = self._get_odm_type(p_val.get('analyzer', None) or p_val['type'])
            collection_data[p_name] = {
                "default": self.DEFAULT_SEARCH_FIELD in p_val.get('copy_to', []),
                "indexed": p_val.get('index', True),
                "list": field_model.multivalued if field_model else False,
                "stored": p_val.get('store', False),
                "type": f_type
            }

        return collection_data

    def _ensure_collection(self):
        if not self.with_retries(self.datastore.client.indices.exists, self.name):
            log.warning(f"Collection {self.name.upper()} does not exists. "
                        "Creating it now...")

            index = deepcopy(default_index)
            if 'settings' not in index:
                index['settings'] = {}
            if 'index' not in index['settings']:
                index['settings']['index'] = {}
            index['settings']['index']['number_of_shards'] = self.shards
            index['settings']['index']['number_of_replicas'] = self.replicas

            mappings = deepcopy(default_mapping)
            if self.model_class:
                mappings['properties'], mappings['dynamic_templates'] = \
                    build_mapping(self.model_class.fields().values())
            else:
                mappings['dynamic_templates'] = deepcopy(default_dynamic_templates)

            if not mappings['dynamic_templates']:
                # Setting dynamic to strict prevents any documents with fields not in the properties to be added
                mappings['dynamic'] = "strict"

            mappings['properties']['id'] = {
                "store": True,
                "doc_values": True,
                "type": 'keyword'
            }

            mappings['properties']['__text__'] = {
                "store": False,
                "type": 'keyword'
            }

            index['mappings'] = mappings
            try:
                self.with_retries(self.datastore.client.indices.create, self.name, index)
            except elasticsearch.exceptions.RequestError as e:
                if not "resource_already_exists_exception" in str(e):
                    raise
                log.warning(f"Tried to create a collection that already exists: {self.name.upper()}")

        self._check_fields()

    def wipe(self):
        log.warning("Wipe operation started for collection: %s" % self.name.upper())

        if self.with_retries(self.datastore.client.indices.exists, self.name):
            self.with_retries(self.datastore.client.indices.delete, self.name)


class ESStore(BaseStore):
    """ Elasticsearch implementation of the ResultStore interface."""
    DEFAULT_SORT = "id asc"
    DATE_FORMAT = {
        'NOW': 'now',
        'YEAR': 'y',
        'MONTH': 'M',
        'WEEK': 'w',
        'DAY': 'd',
        'HOUR': 'h',
        'MINUTE': 'm',
        'SECOND': 's',
        'MILLISECOND': 'ms',
        'MICROSECOND': 'micros',
        'NANOSECOND': 'nanos',
        'SEPARATOR': '||',
        'DATE_END': 'Z'
    }

    def __init__(self, hosts, collection_class=ESCollection):
        super(ESStore, self).__init__(hosts, collection_class)
        tracer = logging.getLogger('elasticsearch')
        tracer.setLevel(logging.CRITICAL)

        self.client = elasticsearch.Elasticsearch(hosts=hosts,
                                                  connection_class=elasticsearch.RequestsHttpConnection,
                                                  max_retries=0)

        self.url_path = 'elastic'

    def __str__(self):
        return '{0} - {1}'.format(self.__class__.__name__, self._hosts)

    def ping(self):
        return self.client.ping()

    def close(self):
        super().close()
        self.client = None

    def connection_reset(self):
        self.client = elasticsearch.Elasticsearch(hosts=self._hosts,
                                                  connection_class=elasticsearch.RequestsHttpConnection,
                                                  max_retries=0)
