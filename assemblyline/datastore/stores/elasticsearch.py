
import json
from copy import copy

from assemblyline.common.datastore_reconnect import DatastoreObjectReconnect
from assemblyline.al.core.datastore import BaseStore, DatastoreObject, SearchException, \
    field_sanitizer, SearchRetryException, config, log

elasticsearch = None


def parse_sort(sort):
    parts = sort.split(' ')
    if len(parts) == 1:
        return [parts]
    elif len(parts) == 2:
        if parts[1] not in ['asc', 'desc']:
            raise SearchException('Unknown sort parameter ' + sort)
        return [{parts[0]: parts[1]}]
    raise SearchException('Unknown sort parameter ' + sort)


class ESObject(DatastoreObject):
    @DatastoreObjectReconnect(log)
    def commit(self, host=None):
        self.datastore.client.indices.refresh(self.name)
        self.datastore.client.indices.clear_cache(self.name)

    @DatastoreObjectReconnect(log)
    def get(self, key, strict=False):
        try:
            return self.datastore.client.get(index=self.name, doc_type='_all', id=key)['_source']
        except elasticsearch.exceptions.NotFoundError:
            return None

    def _save(self, key, data):
        self.datastore.client.update(
            index=self.name,
            doc_type=self.name,
            id=key,
            body=json.dumps({'doc': data, 'doc_as_upsert': True})
        )

    @DatastoreObjectReconnect(log)
    def search(self, query, index=None, **params):
        assert index is None
        return self.datastore.direct_search(self.name, query, **params)['response']

    @DatastoreObjectReconnect(log)
    def stream_keys(self, access_control=None):
        for item in self.datastore.stream_search(self.name, "*", fl=self.datastore.ID, access_control=access_control):
            yield item[self.datastore.ID]

    @DatastoreObjectReconnect(log)
    def delete(self, key):
        try:
            info = self.datastore.client.delete(id=key, doc_type=self.name, index=self.name)
            return info['result'] == 'deleted'
        except elasticsearch.TransportError as error:
            if error.info['result'] == 'not_found':
                return True
            raise

    @DatastoreObjectReconnect(log)
    def histogram(self, field, query, start, end, gap, mincount, filters=(), _hosts_=None):
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": query
                        }
                    }
                }
            },
            "aggregations": {
                "histogram": {
                    ("date_histogram" if isinstance(gap, basestring) else 'histogram'): {
                        "field": field,
                        "interval": gap.strip('+'),
                        "min_doc_count": mincount
                    }
                }
            }
        }

        # Add the histogram bounds as another filter
        filters = [filters] if isinstance(filters, basestring) else list(filters)
        filters.append('{field}:[{min} TO {max}]'.format(field=field, min=start, max=end))

        # Execute the query
        self.datastore.build_query(query_body, filters=filters)
        result = self.datastore.raw_search(self.name, query_body, _hosts_=_hosts_)

        # Convert the histogram into a dictionary
        return {row.get('key_as_string', row['key']): row['doc_count']
                for row in result['aggregations']['histogram']['buckets']}

    @DatastoreObjectReconnect(log)
    def group(self, query, group_on, sort=None, group_sort=None, fields=None, start=None, rows=100,
              filters=(), access_control=None, group_limit=1):
        # This is our minimal query, the following sections will fill it out
        # with whatever extra options the search has been given.
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            # "default_field": df,
                            "query": query
                        }
                    }
                }
            },
            "aggregations": {}
        }

        filters = [filters] if isinstance(filters, basestring) else list(filters)
        if access_control:
            filters.append(access_control)

        if fields:
            fields = fields.split(',')

        self.datastore.build_query(query_body, sort, fields, start=start, filters=filters)

        # Add a group aggregation
        for group_field in group_on:

            top_hits = {
                "size": group_limit
            }

            if group_sort:
                top_hits["sort"] = parse_sort(group_sort)

            query_body["aggregations"]['group-' + group_field] = {
                "terms": {
                    "field": group_field,
                    "size": rows
                },
                "aggregations": {
                    "groupings": {
                        "top_hits": top_hits
                    }
                }
            }

        result = self.datastore.raw_search(self.name, query_body)

        output = {}
        for field in group_on:
            data = result['aggregations']['group-' + field]
            field_output = output[field] = []
            for bucket in data['buckets']:
                field_output.append({
                    'value': bucket['key'],
                    'total': bucket['doc_count'],
                    'items': [ESStore.read_source(row, fields) for row in bucket['groupings']['hits']['hits']]
                })
        return output


class ESBlobObject(ESObject):
    def get(self, key, strict=False):
        value = super(ESBlobObject, self).get(key, strict)
        if value:
            return value['blob']
        return value

    def _save(self, key, data):
        super(ESBlobObject, self)._save(key, {'blob': data})


class ESStore(BaseStore):
    """ Elasticsearch implementation of the ResultStore interface."""
    ID = '_id'
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
    }

    def __init__(self, hosts=None, filestore_factory=None):
        super(ESStore, self).__init__(hosts or self.get_db_node_list(), filestore_factory)
        global elasticsearch
        import elasticsearch
        import elasticsearch.helpers

        self.client = elasticsearch.Elasticsearch(hosts=hosts, connection_class=elasticsearch.RequestsHttpConnection)

        # Initialize solr cores
        self._alerts = ESObject(self, "alert")
        self._blobs = ESBlobObject(self, "blob")
        self._emptyresults = ESObject(self, "emptyresult")
        self._errors = ESObject(self, "error")
        self._files = ESObject(self, "file")
        self._filescores = ESObject(self, "filescore")
        self._nodes = ESObject(self, "node")
        self._results = ESObject(self, "result")
        self._signatures = ESObject(self, "signature")
        self._submissions = ESObject(self, "submission")
        self._users = ESObject(self, "user")
        self._workflows = ESObject(self, "workflow")
        self._apply_proxies()

        self.url_path = 'elastic'

    def __str__(self):
        return '{0} - {1}'.format(self.__class__.__name__, self.hosts)

    @staticmethod
    def build_query(query_body, sort=None, source_filter=None, start=None, rows=None, filters=()):
        # Parse the sort string into the format elasticsearch expects
        if sort:
            query_body['sort'] = parse_sort(sort)

        # Add a field list as a filter on the _source (full document) field
        source_filter = copy(source_filter)
        if source_filter and '_id' in source_filter:
            source_filter.remove('_id')
            query_body['stored_fields'] = ['_id']

        if source_filter:
            query_body['_source'] = source_filter

        # Add an offset/number of results for simple paging
        if start:
            query_body['from'] = start
        if rows:
            query_body['size'] = rows

        # Add filters
        if 'filter' not in query_body['query']['bool']:
            query_body['query']['bool']['filter'] = []
        if isinstance(filters, basestring):
            query_body['query']['bool']['filter'].append({'query_string': {'query': filters}})
        else:
            query_body['query']['bool']['filter'].extend({'query_string': {'query': ff}} for ff in filters)

    def direct_search(self, bucket, query, args=(), start=None, rows=None, sort=None, df="text", wt="json",
                      access_control=None, filters=(), _hosts_=None, fl=None, timeout=None):
        """Attempt to translate solr or function arguments to elasticsearch queries."""
        if bucket not in BaseStore.ALL_INDEXED_BUCKET_LIST:
            raise SearchException("Bucket %s does not exists." % bucket)

        timeout = str(timeout) + 'ms' if timeout else None
        source_filter = fl.split(',') if fl is not None else []

        facet_active = False
        facet_mincount = 1
        facet_fields = []
        filters = list(filters)

        group_active = False
        group_field = None
        group_sort = None
        group_limit = 1

        for key, value in args:
            if key == 'start':
                start = value
            elif key == 'rows':
                rows = value
            elif key == 'timeAllowed':
                timeout = value + 'ms'
            elif key == 'fq':
                filters.append(value)
            elif key == 'q':
                query = value
            elif key == 'sort':
                sort = value
            elif key == 'df':
                df = value
            elif key == 'fl':
                source_filter += value.split(',')
            elif key == 'facet' and value:
                facet_active = True
            elif key == 'facet.mincount':
                facet_mincount = value
            elif key == 'facet.field':
                facet_fields.append(value)
            elif key == 'group' and value:
                group_active = True
            elif key == 'group.field':
                group_field = value
            elif key == 'group.sort':
                group_sort = parse_sort(value)
            elif key == 'group.limit':
                group_limit = value
            else:
                all_args = '; '.join(k + ': ' + v for k, v in args)
                raise ValueError("Unknown query argument: %s %s of [%s]" % (key, value, all_args))

        # This is our minimal query, the following sections will fill it out
        # with whatever extra options the search has been given.
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "default_field": df,
                            "query": query
                        }
                    }
                }
            }
        }

        # Add a filter query to the search
        if access_control:
            if isinstance(access_control, basestring):
                filters.append(access_control)
            else:
                filters.extend(access_control)

        # Time limit for the query
        if timeout:
            query_body['timeout'] = timeout

        # Add a facet aggregation
        if facet_active:
            query_body["aggregations"] = {}
            for field in facet_fields:
                query_body["aggregations"][field] = {
                    "terms": {
                        "field": field,
                        "min_doc_count": facet_mincount
                    }
                }

        # Add a group aggregation
        if group_active:
            query_body["aggregations"] = query_body.get("aggregations", {})
            for field in [group_field]:
                query_body["aggregations"]['group-' + field] = {
                    "terms": {
                        "field": field,
                    },
                    "aggregations": {
                        "groupings": {
                            "top_hits": {
                                "sort": group_sort,
                                "size": group_limit
                            }
                        }
                    }
                }

        # Add all the other query parameters
        self.build_query(query_body, sort, source_filter, start, rows, filters=filters)

        try:
            # Run the query
            result = self.raw_search(bucket=bucket, query=query_body, _hosts_=_hosts_)

            # Unpack the results, ensure the id is always set
            docs = [self.read_source(doc, source_filter) for doc in result['hits']['hits']]
            for doc, resp in zip(docs, result['hits']['hits']):
                doc.update(_id=resp['_id'])

            output = {
                'provider': 'elasticsearch',
                'response': {
                    'num_found': result['hits']['total'],
                    'numFound': result['hits']['total'],
                    'docs': docs
                }
            }

            if facet_active:
                # Elastic search will come back with something with this format:
                # 'aggregations': {
                #     <query name (given field name)>: {
                #         'buckets': [{'key': 'admin', 'doc_count': 1}, {'key': 'user', 'doc_count': 5}],
                #     }
                # }
                #
                # Need to make it match the solr format for the same data:
                # 'facet_counts': {
                #     'facet_fields': {
                #          <fieldname>: ['admin', 1, 'user', 5]
                #     }
                # }
                facet_results = {}
                for field, data in result['aggregations'].items():
                    field_row = []
                    for bucket in data['buckets']:
                        field_row.append(bucket['key'])
                        field_row.append(bucket['doc_count'])
                    facet_results[field] = field_row

                output['facet_counts'] = {'facet_fields': facet_results}

            if group_active:
                # We are using an elasticsearch aggregation to do grouping, so the
                # output is similar to the above, but each bucket also has a document
                # set at: buckets.##.groupings.hits.hits
                #
                # solr group output:
                # 'grouped': {<field>: {'matches': ##, 'groups':[{
                #   'groupValue': <field value>,
                #   'docList': {'numFound': ##, 'start': ##, 'docs': [<limit documents>]}
                # }]}}
                output['grouped'] = group_results = {}

                for field in [group_field]:
                    data = result['aggregations']['group-' + field]
                    groups = []
                    group_results[field] = {'matches': len(data['buckets']), 'groups': groups}
                    for bucket in data['buckets']:
                        groups.append({
                            'groupValue': bucket['key'],
                            'docList': {
                                'start': 0,
                                'numFound': bucket['doc_count'],
                                'docs': [self.read_source(row, source_filter)
                                         for row in bucket['groupings']['hits']['hits']]
                            }
                        })

            return output

        except (elasticsearch.TransportError, elasticsearch.ConnectionError, elasticsearch.ConnectionTimeout) as error:
            raise SearchRetryException("bucket: %s, query: %s, error: %s" % (bucket, query, str(error)))
        except Exception as error:
            raise SearchException("bucket: %s, query: %s, error: %s" % (bucket, query, str(error)))

    @classmethod
    def read_source(cls, result, fields=None):
        out = result.get('_source', {})
        if fields is None or '*' in fields or cls.ID in fields:
            out[cls.ID] = result[cls.ID]
        return out

    def raw_search(self, bucket, query, _hosts_=None):
        if bucket not in BaseStore.ALL_INDEXED_BUCKET_LIST:
            raise SearchException("Bucket %s does not exists." % bucket)

        # Select either the default client or build one from custom hosts for this query
        client = self.client if _hosts_ is None else elasticsearch.Elasticsearch(_hosts_)

        try:
            # Run the query
            return client.search(index=bucket, body=json.dumps(query))

        except (elasticsearch.TransportError, elasticsearch.ConnectionError, elasticsearch.ConnectionTimeout) as error:
            raise SearchRetryException("bucket: %s, query: %s, error: %s" % (bucket, query, str(error)))
        except Exception as error:
            raise SearchException("bucket: %s, query: %s, error: %s" % (bucket, query, str(error)))

    def stream_search(self, bucket, query, df="text", sort=None, fl=None, item_buffer_size=200, access_control=None, fq=None):
        if item_buffer_size > 500 or item_buffer_size < 50:
            raise SearchException("Variable item_buffer_size must be between 50 and 500.")
        assert sort is None

        if query in ["*", "*:*"] and fl != self.ID:
            raise SearchException("You did not specified a query, you just asked for everything... Play nice.")

        query_body = {"query": {"bool": {"must": {"query_string": {"query": query}}}}}

        # Add a filter query to the search
        if access_control:
            query_body['query']['bool']['filter'] = {'query_string': {'query': access_control}}

        # Add a field list as a filter on the _source (full document) field
        if fl:
            query_body['_source'] = fl

        iterator = elasticsearch.helpers.scan(
            self.client,
            query=query_body,
            index=bucket,
            doc_type=bucket,
            preserve_order=sort is not None
        )

        for value in iterator:
            # Unpack the results, ensure the id is always set
            yield self.read_source(value, fl)

    # noinspection PyBroadException
    def datastore_connection_reset(self):
        self.client = elasticsearch.Elasticsearch(hosts=self.hosts, connection_class=elasticsearch.RequestsHttpConnection)

    def get_db_node_list(self, full=True):
        return config.datastore.get('elasticsearch', {}).get('nodes', [])

    def generate_field_list(self, get_full_list, specific_bucket=None):
        if specific_bucket and (specific_bucket in BaseStore.INDEXED_BUCKET_LIST
                                or specific_bucket in BaseStore.ADMIN_INDEXED_BUCKET_LIST):
            bucket_list = [specific_bucket]
        elif not specific_bucket:
            bucket_list = list(BaseStore.INDEXED_BUCKET_LIST)
            if get_full_list:
                bucket_list += BaseStore.ADMIN_INDEXED_BUCKET_LIST
        else:
            bucket_list = []

        def flatten_fields(props):
            out = {}
            for name, value in props.items():
                if 'properties' in value:
                    for child, ctype in flatten_fields(value['properties']).items():
                        out[name + '.' + child] = ctype
                elif 'type' in value:
                    out['name'] = value['type']
                else:
                    raise ValueError("Unknown field data " + str(props))
            return out

        output = {}
        for bucket_name in bucket_list:
            data = self.client.indices.get(bucket_name)

            properties = flatten_fields(data[bucket_name]['mappings'][bucket_name].get('properties', {}))

            bucket_data = {}

            for k, v in properties.items():
                if k.startswith("_") or "//" in k:
                    continue
                if not field_sanitizer.match(k):
                    continue

                bucket_data[k] = {
                    "indexed": True,
                    "stored": True,
                    "list": True,
                    "type": v
                }

            output[bucket_name] = bucket_data

        return output
