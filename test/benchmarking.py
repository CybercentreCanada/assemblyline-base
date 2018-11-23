"""
Utilities for benchmarking the datastore modules.
"""
from assemblyline.datastore import odm
from assemblyline.datastore import log
import concurrent.futures
import logging
import arrow
import random
import time
from pprint import pprint
import string


DATASET_SIZE = 1000


def setup_collection(datastore, model, use_model):
    collection_name = ''.join(random.choices(string.ascii_lowercase, k=10))
    datastore.register(collection_name, model)
    col = datastore.__getattr__(collection_name)
    del datastore._collections[collection_name]

    if not use_model:
        col.model_class = None

    return col


def solr_connection(model, use_model=True):
    from assemblyline.datastore.stores.solr_store import SolrStore
    return setup_collection(SolrStore(['127.0.0.1']), model, use_model)


def es_connection(model, use_model=True):
    from assemblyline.datastore.stores.es_store import ESStore
    return setup_collection(ESStore(['127.0.0.1']), model, use_model)


def riak_connection(model, use_model=True):
    from assemblyline.datastore.stores.riak_store import RiakStore
    return setup_collection(RiakStore(['127.0.0.1']), model, use_model)


@odm.model(index=True, store=True)
class BModel(odm.Model):
    depth = odm.Integer()
    width = odm.Integer()


@odm.model(index=True, store=True)
class AModel(odm.Model):
    flavour = odm.Text(copyto='features')
    height = odm.Integer()
    birthday = odm.Date()
    tags = odm.List(odm.Keyword(), default=[], copyto='features')
    size = odm.Compound(BModel, default={'depth': 100, 'width': 100})
    features = odm.List(odm.Text(), default=[])
    counter = odm.Integer()


def measure(data, key):
    class _timer:
        def __enter__(self):
            self.start = time.time()

        def __exit__(self, *args):
            data[key] = time.time() - self.start
    return _timer()


def run(ds, times, dataset):
    pool = concurrent.futures.ThreadPoolExecutor(20)

    # Insert the data
    with measure(times, 'insertion'):
        results = [pool.submit(ds.save, key, value) for key, value in dataset.items()]
        # results = pool.map(ds, dataset.items())
        concurrent.futures.wait(results)
        ds.commit()
    [res.result() for res in results]

    with measure(times, 'range_searches_10'):
        results = []
        for _ in range(1000):
            index = random.randint(0, DATASET_SIZE)
            results.append(pool.submit(ds.search, f'counter: [{index} TO {index + 10}]'))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    with measure(times, 'range_searches_100'):
        results = []
        for _ in range(1000):
            index = random.randint(0, DATASET_SIZE)
            results.append(pool.submit(ds.search, f'counter: [{index} TO {index + 100}]'))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    # with measure(times, 'delete_10'):
    #     results = []
    #     for _ in range(1000):
    #         index = random.randint(0, DATASET_SIZE)
    #         results.append(pool.submit(ds.delete, f'counter: [{index} TO {index + 100}]'))
    #     concurrent.futures.wait(results)
    #     ds.commit()
    # [res.result() for res in results]

    pool.shutdown()


def random_string(min_length, max_length):
    length = random.choice(range(min_length, max_length))
    return ''.join(random.choices(string.ascii_letters, k=length))


def main():
    datastores = {}
    try:
        data = {}

        for ii in range(DATASET_SIZE):
            row = {
                'flavour': random_string(50, 100),
                'height': random.choice(range(90, 200, 5)),
                'birthday': arrow.utcnow().isoformat().replace('+00:00', 'Z'),
                'tags': [random_string(5, 10) for _ in range(random.choice(range(5)))],
                'size.depth': 1000,
                'size.width': 5000,
                'counter': ii
            }

            data[str(ii)] = row

        datastores = {
            'riak': riak_connection(AModel, False),
            'riak_model': riak_connection(AModel),
            'solr': solr_connection(AModel, False),
            'solr_model': solr_connection(AModel),
            'es': es_connection(AModel, False),
            'es_model': es_connection(AModel),
        }

        result = {}
        for name, ds in datastores.items():
            result[name] = {}
            run(ds, result[name], data)

        pprint(result)

    finally:
        log.setLevel(logging.ERROR)
        for store in datastores.values():
            store.wipe()


if __name__ == '__main__':
    main()
