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
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.randomizer import random_model_obj

DATASET_SIZE = 1000


def setup_collection(datastore, model, use_model):
    collection_name = ''.join(random.choices(string.ascii_lowercase, k=10))
    print(f"\t{datastore.__class__.__name__} [{collection_name}] - model:{use_model}")
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
    start_time = time.time()
    # Insert the data
    print(f"\tInsert {DATASET_SIZE} documetns benchmark ({int(time.time()-start_time)})")
    with measure(times, 'insertion'):
        results = [pool.submit(ds.save, key, value) for key, value in dataset.items()]
        concurrent.futures.wait(results)
        ds.commit()
    [res.result() for res in results]

    print(f"\tGet {DATASET_SIZE} documents benchmark ({int(time.time()-start_time)})")
    with measure(times, 'get_all'):
        results = []
        for ii in range(DATASET_SIZE):
            results.append(pool.submit(ds.get, str(ii)))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    print(f"\tSearch 1 row benchmark ({int(time.time()-start_time)})")
    with measure(times, 'search'):
        results = []
        for ii in range(DATASET_SIZE):
            results.append(pool.submit(ds.search, f'id:{str(ii)}', rows=1))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    print(f"\tRange Search 50 rows benchmark ({int(time.time()-start_time)})")
    with measure(times, 'range_searches_50'):
        results = []
        for ii in range(DATASET_SIZE):
            results.append(pool.submit(ds.search, f'max_score:[{str(ii)} TO {str(ii+500)}]', rows=50))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    print(f"\tHistogram benchmark ({int(time.time()-start_time)})")
    with measure(times, 'histogram'):
        results = []
        for _ in range(DATASET_SIZE):
            results.append(pool.submit(ds.histogram,
                                       "times.submitted",
                                       f"{ds.datastore.now}-1{ds.datastore.hour}",
                                       ds.datastore.now,
                                       f"+1{ds.datastore.minute}"))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    print(f"\tFacet benchmark ({int(time.time()-start_time)})")
    with measure(times, 'facet'):
        results = []
        for _ in range(DATASET_SIZE):
            results.append(pool.submit(ds.field_analysis, "errors"))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    print(f"\tGrouping benchmark ({int(time.time()-start_time)})")
    with measure(times, 'groups'):
        results = []
        for _ in range(DATASET_SIZE):
            results.append(pool.submit(ds.grouped_search, 'state', rows=10))
        concurrent.futures.wait(results)
    [res.result() for res in results]

    print(f"\tDelete {DATASET_SIZE/10} documents benchmark ({int(time.time()-start_time)})")
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

        print(f"\nGenerating random dataset of {DATASET_SIZE} documents...")
        for ii in range(DATASET_SIZE):
            data[str(ii)] = random_model_obj(Submission, as_json=True)

        print("Creating indexes...")
        log.setLevel(logging.ERROR)
        datastores = {
            'riak': riak_connection(Submission, False),
            'riak_model': riak_connection(Submission),
            'solr': solr_connection(Submission, False),
            'solr_model': solr_connection(Submission),
            'es': es_connection(Submission, False),
            'es_model': es_connection(Submission),
        }
        log.setLevel(logging.INFO)

        result = {}
        for name, ds in datastores.items():
            print(f"\nPerforming benchmarks for datastore: {name}")
            result[name] = {}
            run(ds, result[name], data)

        data = [
            [
                k, v['get_all'],
                v['insertion'],
                v[f'delete_{int(DATASET_SIZE/10)}'],
                v['search'],
                v['range_searches_50'],
                v['histogram'],
                v['facet'],
                v['groups']
            ] for k, v in result.items()]

        print("\n\n")
        print(tabulate(data, headers=['Datastore',
                                      f'GETs {DATASET_SIZE}',
                                      f'PUTs {DATASET_SIZE}',
                                      f'DEL {int(DATASET_SIZE/10)}',
                                      f'Search {DATASET_SIZE} docs',
                                      f'Search {50*DATASET_SIZE} docs',
                                      f'histogram',
                                      f'facet',
                                      f'groups']))
        print("\n\n")

    finally:
        log.setLevel(logging.ERROR)
        print("Wiping data on all datastores...")
        for store in datastores.values():
            store.wipe()


if __name__ == '__main__':
    main()
