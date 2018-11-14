
import elasticsearch
import elasticsearch.helpers
import json
import logging
import time

from copy import deepcopy

from assemblyline.datastore import Collection, collection_reconnect, BaseStore, SearchException, \
    SearchRetryException, log
from assemblyline.datastore.support.elasticsearch.schemas import default_index, default_mapping, \
    default_dynamic_templates
from assemblyline.datastore.support.elasticsearch.build import build_mapping, back_mapping
from assemblyline.datastore import odm


def _strip_lists(model, data):
    """Elasticsearch returns everything as lists, regardless of whether
    we want the field to be multi-valued or not. This method uses the model's
    knowlage of what should or should not have multiple values to fix the data.
    """
    fields = model.fields()
    out = {}
    for key, value in odm.flat_to_nested(data).items():
        doc_type = fields[key]
        if isinstance(doc_type, odm.List):
            out[key] = value
        elif isinstance(doc_type, odm.Compound):
            out[key] = _strip_lists(doc_type.child_type, value)
        else:
            out[key] = value[0]
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
        return {('_id_' if key == '_id' else key): value for key, value in sort.items()}

    parts = sort.split(' ')
    if len(parts) == 1:
        if parts == '_id':
            return ['_id_']
        return [parts]
    elif len(parts) == 2:
        if parts[1] not in ['asc', 'desc']:
            raise SearchException('Unknown sort parameter ' + sort)
        if parts[0] == '_id':
            return [{'_id_': parts[1]}]
        return [{parts[0]: parts[1]}]
    raise SearchException('Unknown sort parameter ' + sort)


class ESCollection(Collection):
    DEFAULT_SORT = [{'_id': 'asc'}]
    DEFAULT_SEARCH_FIELD = '__text__'
    MAX_SEARCH_ROWS = 500
    MAX_GROUP_LIMIT = 10
    MAX_FACET_LIMIT = 100
    DEFAULT_SEARCH_VALUES = {
        'timeout': None,
        'field_list': None,
        'facet_active': False,
        'facet_mincount': 1,
        'facet_fields': [],
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

    def __init__(self, datastore, name, model_class=None, replicas=0):
        self.replicas = replicas

        super().__init__(datastore, name, model_class=model_class)

    @collection_reconnect(log)
    def commit(self):
        self.datastore.client.indices.refresh(self.name)
        self.datastore.client.indices.clear_cache(self.name)
        return True

    @collection_reconnect(log)
    def multiget(self, key_list):
        data = self.datastore.client.mget({'ids': key_list}, index=self.name, doc_type='_all')
        out = []
        for row in data.get('docs', []):
            if 'found' in row and not row['found']:
                raise KeyError(row['_id'])
            if '__non_doc_raw__' in row['_source']:
                out.append(row['_source']['__non_doc_raw__'])
            else:
                row['_source'].pop(self.datastore.SORT_ID, None)
                out.append(self.normalize(row['_source']))
        return out

    @collection_reconnect(log)
    def _get(self, key, retries):
        if retries is None:
            retries = self.RETRY_NONE

        done = False
        while not done:

            try:
                data = self.datastore.client.get(index=self.name, doc_type='_all', id=key)['_source']
                # TODO: Maybe we should not allow data that is not a dictionary...
                if "__non_doc_raw__" in data:
                    return data['__non_doc_raw__']
                data.pop(self.datastore.SORT_ID, None)
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
        try:
            saved_data = data.as_primitives()
        except AttributeError:
            if not isinstance(data, dict):
                saved_data = {'__non_doc_raw__': data}
            else:
                saved_data = deepcopy(data)

        saved_data[self.datastore.SORT_ID] = key

        self.datastore.client.update(
            index=self.name,
            doc_type=self.name,
            id=key,
            body=json.dumps({'doc': saved_data, 'doc_as_upsert': True})
        )

        return True

    @collection_reconnect(log)
    def delete(self, key):
        try:
            info = self.datastore.client.delete(id=key, doc_type=self.name, index=self.name)
            return info['result'] == 'deleted'
        except elasticsearch.NotFoundError:
            return True

    @collection_reconnect(log)
    def delete_matching(self, query):
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
            info = self.datastore.client.delete_by_query(index=self.name, body=query_body, doc_type=self.name)
            return info.get('deleted', 0) != 0
        except elasticsearch.NotFoundError:
            return False

    @collection_reconnect(log)
    def _update(self, key, operations):
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

        update_body = {
            "script": {
                "lang": "painless",
                "source": """;\n""".join(op_sources),
                "params": op_params
            }
        }

        # noinspection PyBroadException
        try:
            res = self.datastore.client.update(index=self.name, doc_type=self.name, id=key, body=update_body)
        except Exception:
            return False

        return res['result'] == "updated"

    def _format_output(self, result, fields=None):
        source = result.get('fields', {})

        if self.model_class:
            item_id = result['_id']
            source = result.get('fields', {})
            if fields and '*' in fields:
                fields = None

            if '_source' in source:
                source['_source'].pop(self.datastore.SORT_ID, None)
                return self.model_class(source['_source'], docid=item_id)

            source.pop(self.datastore.SORT_ID, None)
            source = _strip_lists(self.model_class, source)
            return self.model_class(source, mask=fields, docid=item_id)

        if isinstance(fields, str):
            fields = fields

        if fields is None or '*' in fields or self.datastore.ID in fields:
            source[self.datastore.ID] = [result[self.datastore.ID]]

        if fields is None or '*' in fields:
            return source

        return {key: val for key, val in source.items() if key in fields}

    def _cleanup_search_result(self, item):
        if isinstance(item, dict):
            item.pop('_source', None)
            item.pop('_version', None)
            item.pop(self.DEFAULT_SEARCH_FIELD, None)

        return item

    @collection_reconnect(log)
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

        # Add a group aggregation
        if parsed_values['group_active']:
            query_body["collapse"] = {
                "field": parsed_values['group_field'],
                "inner_hits": {
                    "name": "group",
                    "stored_fields": parsed_values['field_list'] or ['*'],
                    "size": parsed_values['group_limit'],
                    "sort": parsed_values['group_sort'] or [{parsed_values['group_field']: 'asc'}]
                }
            }

        try:
            # Run the query
            result = self.datastore.client.search(index=self.name, body=json.dumps(query_body))
            return result

        except elasticsearch.RequestError:
            raise

        except (elasticsearch.TransportError, elasticsearch.ConnectionError, elasticsearch.ConnectionTimeout) as error:
            raise SearchRetryException("collection: %s, query: %s, error: %s" % (self.name, query_body, str(error)))

        except Exception as error:
            raise SearchException("collection: %s, query: %s, error: %s" % (self.name, query_body, str(error)))

    def search(self, query, offset=0, rows=None, sort=None,
               fl=None, timeout=None, filters=None, access_control=None):

        if not rows:
            rows = self.DEFAULT_ROW_SIZE

        if not sort:
            sort = self.DEFAULT_SORT

        if not filters:
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

        docs = [self._format_output(doc, field_list) for doc in result['hits']['hits']]
        output = {
            "offset": int(offset),
            "rows": int(rows),
            "total": int(result['hits']['total']),
            "items": [self._cleanup_search_result(x) for x in docs]
        }
        return output

    def stream_search(self, query, fl=None, filters=None, access_control=None, item_buffer_size=200):
        if item_buffer_size > 500 or item_buffer_size < 50:
            raise SearchException("Variable item_buffer_size must be between 50 and 500.")

        if query in ["*", "*:*"] and fl != self.datastore.ID:
            raise SearchException("You did not specified a query, you just asked for everything... Play nice.")

        if not filters:
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
                            "default_field": self.datastore.ID,
                            "query": query
                        }
                    },
                    'filter': [{'query_string': {'query': ff}} for ff in filters]
                }
            },
            "sort": parse_sort(self.datastore.DEFAULT_SORT),
            "stored_fields": fl or ['*']
        }

        iterator = elasticsearch.helpers.scan(
            self.datastore.client,
            query=query_body,
            index=self.name,
            doc_type=self.name,
            preserve_order=True
        )

        for value in iterator:
            # Unpack the results, ensure the id is always set
            yield self._format_output(value, fl)

    @collection_reconnect(log)
    def histogram(self, field, start, end, gap, query="*", mincount=1, filters=None, access_control=None):
        type_modifier = self._validate_steps_count(start, end, gap)

        if not filters:
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

    @collection_reconnect(log)
    def field_analysis(self, field, query="*", prefix=None, contains=None, ignore_case=False, sort=None, limit=10,
                       min_count=1, filters=None, access_control=None):
        if not filters:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('facet_active', True),
            ('facet_fields', [field]),
            ('facet_mincount', min_count)
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

    @collection_reconnect(log)
    def grouped_search(self, group_field, query="*", offset=0, sort=None, group_sort=None, fl=None, limit=1,
                       rows=None, filters=None, access_control=None):

        if not rows:
            rows = self.DEFAULT_ROW_SIZE

        if not sort:
            sort = self.DEFAULT_SORT

        if not group_sort:
            group_sort = self.DEFAULT_SORT

        if not filters:
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
            'total': result['hits']['total'],
            'items': [{
                'value': collapsed['fields'][group_field][0],
                'total': collapsed['inner_hits']['group']['hits']['total'],
                'items': [self._cleanup_search_result(self._format_output(row, field_list))
                          for row in collapsed['inner_hits']['group']['hits']['hits']]
            } for collapsed in result['hits']['hits']]
        }

    @staticmethod
    def _get_odm_type(ds_type):
        try:
            return back_mapping[ds_type].__name__.lower()
        except KeyError:
            return ds_type.lower()

    @collection_reconnect(log)
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

        data = self.datastore.client.indices.get(self.name)

        properties = flatten_fields(data[self.name]['mappings'][self.name].get('properties', {}))

        collection_data = {}

        for p_name, p_val in properties.items():
            if p_name.startswith("_") or "//" in p_name:
                continue
            if not Collection.FIELD_SANITIZER.match(p_name):
                continue

            f_type = self._get_odm_type(p_val.get('analyzer', None) or p_val['type'])
            collection_data[p_name] = {
                "indexed": p_val.get('index', None) or True,
                "stored": p_val.get('store', None) or False,
                "type": f_type
            }

        return collection_data

    @collection_reconnect(log)
    def _ensure_collection(self):
        if not self.datastore.client.indices.exists(self.name):
            log.warning(f"Collection {self.name.upper()} does not exists. "
                        "Creating it now...")

            index = deepcopy(default_index)
            if 'settings' not in index:
                index['settings'] = {}
            if 'index' not in index['settings']:
                index['settings']['index'] = {}
            index['settings']['index']['number_of_replicas'] = self.replicas

            mappings = deepcopy(default_mapping)
            if self.model_class:
                mappings['properties'] = build_mapping(self.model_class.fields().values())
            else:
                mappings['dynamic'] = True
                mappings['dynamic_templates'] = deepcopy(default_dynamic_templates)

            mappings['properties'][self.datastore.SORT_ID] = {
                "store": True,
                "doc_values": True,
                "type": 'keyword'
            }

            index['mappings'][self.name] = mappings
            self.datastore.client.indices.create(self.name, index)
        self._check_fields()

    @collection_reconnect(log)
    def wipe(self):
        log.warning("Wipe operation started for collection: %s" % self.name.upper())

        if self.datastore.client.indices.exists(self.name):
            self.datastore.client.indices.delete(self.name)


class ESStore(BaseStore):
    """ Elasticsearch implementation of the ResultStore interface."""
    ID = '_id'
    SORT_ID = '_id_'
    DEFAULT_SORT = "_id asc"
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

        self.client = elasticsearch.Elasticsearch(hosts=hosts, connection_class=elasticsearch.RequestsHttpConnection)

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
                                                  connection_class=elasticsearch.RequestsHttpConnection)
