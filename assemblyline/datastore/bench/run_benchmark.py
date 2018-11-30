"""
Utilities for benchmarking the datastore modules.
"""
import concurrent.futures
import logging
import random
import time
import string

from tabulate import tabulate

from assemblyline.datastore import log
from assemblyline.datastore.bench.data_generator import get_random_submission
from assemblyline.datastore.bench.model import FakeSubmission

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
        concurrent.futures.wait(results)
        ds.commit()
    [res.result() for res in results]

    with measure(times, 'get_all'):
        results = []
        for ii in range(DATASET_SIZE):
            results.append(pool.submit(ds.get, str(ii)))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    with measure(times, 'search'):
        results = []
        for _ in range(DATASET_SIZE):
            index = random.randint(0, DATASET_SIZE)
            results.append(pool.submit(ds.search, f'max_score:{index}'))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    with measure(times, 'range_searches_10'):
        results = []
        for _ in range(DATASET_SIZE):
            index = random.randint(0, DATASET_SIZE)
            results.append(pool.submit(ds.search, f'max_score:[{index} TO {index + 10}]'))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    with measure(times, 'range_searches_50'):
        results = []
        for _ in range(DATASET_SIZE):
            index = random.randint(0, DATASET_SIZE)
            results.append(pool.submit(ds.search, f'max_score:[{index} TO {index + 50}]'))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    with measure(times, f'delete_{int(DATASET_SIZE/10)}'):
        results = []
        for ii in range(int(DATASET_SIZE/10)):
            results.append(pool.submit(ds.delete, str(ii)))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    pool.shutdown()


def random_string(min_length, max_length):
    length = random.choice(range(min_length, max_length))
    return ''.join(random.choices(string.ascii_letters, k=length))


def main():
    datastores = {}
    try:
        data = {}

        for ii in range(DATASET_SIZE):
            data[str(ii)] = get_random_submission(as_model=False)

        print("\nCreating indexes...\n")
        log.setLevel(logging.ERROR)
        datastores = {
            'riak': riak_connection(FakeSubmission, False),
            'riak_model': riak_connection(FakeSubmission),
            'solr': solr_connection(FakeSubmission, False),
            'solr_model': solr_connection(FakeSubmission),
            'es': es_connection(FakeSubmission, False),
            'es_model': es_connection(FakeSubmission),
        }
        log.setLevel(logging.INFO)

        result = {}
        for name, ds in datastores.items():
            print(f"Performing benchmarks for datastore: {name}")
            result[name] = {}
            run(ds, result[name], data)

        data = [[k, v['get_all'], v['insertion'], v[f'delete_{int(DATASET_SIZE/10)}'],
                 v['search'], v['range_searches_10'], v['range_searches_50']]
                for k, v in result.items()]

        print("\n\n")
        print(tabulate(data, headers=['Datastore', f'GETs {DATASET_SIZE}', f'PUTs {DATASET_SIZE}',
                                      f'DEL {int(DATASET_SIZE/10)}', 'Search 1', 'Search 10', 'Search 50']))

    finally:
        log.setLevel(logging.ERROR)
        for store in datastores.values():
            store.wipe()


if __name__ == '__main__':
    main()
