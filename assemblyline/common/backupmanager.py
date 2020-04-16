
import json
import os
import random
import time
import threading

from multiprocessing import Process

from assemblyline.common import forge
from assemblyline.common.uid import get_random_id
from assemblyline.odm.models.error import ERROR_TYPES
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.queues.named import NamedQueue


# noinspection PyBroadException
def backup_worker(worker_id, instance_id, working_dir):
    datastore = forge.get_datastore(archive_access=True)
    worker_queue = NamedQueue(f"r-worker-{instance_id}", ttl=1800)
    done_queue = NamedQueue(f"r-done-{instance_id}", ttl=1800)
    hash_queue = Hash(f"r-hash-{instance_id}")
    stopping = False
    with open(os.path.join(working_dir, "backup.part%s" % worker_id), "w+") as backup_file:
        while True:
            data = worker_queue.pop(timeout=1)
            if data is None:
                if stopping:
                    break
                continue

            if data.get('stop', False):
                if not stopping:
                    stopping = True
                else:
                    time.sleep(round(random.uniform(0.050, 0.250), 3))
                    worker_queue.push(data)
                continue

            missing = False
            success = True
            try:
                to_write = datastore.get_collection(data['bucket_name']).get(data['key'], as_obj=False)
                if to_write:
                    if data.get('follow_keys', False):
                        for bucket, bucket_key, getter in FOLLOW_KEYS.get(data['bucket_name'], []):
                            for key in getter(to_write.get(bucket_key, None)):
                                hash_key = "%s_%s" % (bucket, key)
                                if not hash_queue.exists(hash_key):
                                    hash_queue.add(hash_key, "True")
                                    worker_queue.push({"bucket_name": bucket, "key": key, "follow_keys": True})

                    backup_file.write(json.dumps((data['bucket_name'], data['key'], to_write)) + "\n")
                else:
                    missing = True
            except Exception:
                success = False

            done_queue.push({
                "success": success,
                "missing": missing,
                "bucket_name": data['bucket_name'],
                "key": data['key']
            })

    done_queue.push({"stopped": True})


# noinspection PyBroadException
def restore_worker(worker_id, instance_id, working_dir):
    datastore = forge.get_datastore(archive_access=True)
    done_queue = NamedQueue(f"r-done-{instance_id}", ttl=1800)

    with open(os.path.join(working_dir, "backup.part%s" % worker_id), "rb") as input_file:
        for line in input_file:
            bucket_name, key, data = json.loads(line)

            success = True
            try:
                collection = datastore.get_collection(bucket_name)
                collection.save(key, data)
            except Exception:
                success = False

            done_queue.push({
                "success": success,
                "missing": False,
                "bucket_name": bucket_name,
                "key": key})

    done_queue.push({"stopped": True})


class DistributedBackup(object):
    def __init__(self, working_dir, worker_count=50, spawn_workers=True, use_threading=False, logger=None):
        self.working_dir = working_dir
        self.datastore = forge.get_datastore(archive_access=True)
        self.logger = logger
        self.plist = []
        self.use_threading = use_threading
        self.instance_id = get_random_id()
        self.worker_queue = NamedQueue(f"r-worker-{self.instance_id}", ttl=1800)
        self.done_queue = NamedQueue(f"r-done-{self.instance_id}", ttl=1800)
        self.hash_queue = Hash(f"r-hash-{self.instance_id}")
        self.bucket_error = []
        self.VALID_BUCKETS = sorted(list(self.datastore.ds.get_models().keys()))
        self.worker_count = worker_count
        self.spawn_workers = spawn_workers
        self.total_count = 0
        self.error_map_count = {}
        self.missing_map_count = {}
        self.map_count = {}
        self.last_time = 0
        self.last_count = 0
        self.error_count = 0

    def cleanup(self):
        self.worker_queue.delete()
        self.done_queue.delete()
        self.hash_queue.delete()
        for p in self.plist:
            p.terminate()

    def done_thread(self, title):
        t0 = time.time()
        self.last_time = t0

        running_threads = self.worker_count

        while running_threads > 0:
            msg = self.done_queue.pop(timeout=1)

            if msg is None:
                continue

            if "stopped" in msg:
                running_threads -= 1
                continue

            bucket_name = msg.get('bucket_name', 'unknown')

            if msg.get('success', False):
                self.total_count += 1

                if msg.get("missing", False):
                    if bucket_name not in self.missing_map_count:
                        self.missing_map_count[bucket_name] = 0

                    self.missing_map_count[bucket_name] += 1
                else:
                    if bucket_name not in self.map_count:
                        self.map_count[bucket_name] = 0

                    self.map_count[bucket_name] += 1

                new_t = time.time()
                if (new_t - self.last_time) > 5:
                    if self.logger:
                        self.logger.info("%s (%s at %s keys/sec) ==> %s" %
                                         (self.total_count,
                                          new_t - self.last_time,
                                          int((self.total_count - self.last_count) / (new_t - self.last_time)),
                                          self.map_count))
                    self.last_count = self.total_count
                    self.last_time = new_t
            else:
                self.error_count += 1

                if bucket_name not in self.error_map_count:
                    self.error_map_count[bucket_name] = 0

                self.error_map_count[bucket_name] += 1

        # Cleanup
        self.cleanup()

        summary = ""
        summary += "\n########################\n"
        summary += "####### SUMMARY  #######\n"
        summary += "########################\n"
        summary += "%s items - %s errors - %s secs\n\n" % \
                   (self.total_count, self.error_count, time.time() - t0)

        for k, v in self.map_count.items():
            summary += "\t%15s: %s\n" % (k.upper(), v)

        if len(self.missing_map_count.keys()) > 0:
            summary += "\n\nMissing data:\n\n"
            for k, v in self.missing_map_count.items():
                summary += "\t%15s: %s\n" % (k.upper(), v)

        if len(self.error_map_count.keys()) > 0:
            summary += "\n\nErrors:\n\n"
            for k, v in self.error_map_count.items():
                summary += "\t%15s: %s\n" % (k.upper(), v)

        if len(self.bucket_error) > 0:
            summary += f"\nThese buckets failed to {title.lower()} completely: {self.bucket_error}\n"
        if self.logger:
            self.logger.info(summary)

    # noinspection PyBroadException,PyProtectedMember
    def backup(self, bucket_list, follow_keys=False, query=None):
        if query is None:
            query = 'id:*'

        for bucket in bucket_list:
            if bucket not in self.VALID_BUCKETS:
                if self.logger:
                    self.logger.warn("\n%s is not a valid bucket.\n\n"
                                     "The list of valid buckets is the following:\n\n\t%s\n" %
                                     (bucket.upper(), "\n\t".join(self.VALID_BUCKETS)))
                return

        targets = ', '.join(bucket_list)
        try:
            if self.logger:
                self.logger.info("\n-----------------------")
                self.logger.info("----- Data Backup -----")
                self.logger.info("-----------------------")
                self.logger.info(f"    Deep: {follow_keys}")
                self.logger.info(f"    Buckets: {targets}")
                self.logger.info(f"    Workers: {self.worker_count}")
                self.logger.info(f"    Target directory: {self.working_dir}")
                self.logger.info(f"    Filtering query: {query}")

            # Start the workers
            for x in range(self.worker_count):
                if self.use_threading:
                    t = threading.Thread(target=backup_worker, args=(x, self.instance_id, self.working_dir))
                    t.setDaemon(True)
                    t.start()
                else:
                    p = Process(target=backup_worker, args=(x, self.instance_id, self.working_dir))
                    p.start()
                    self.plist.append(p)

            # Start done thread
            dt = threading.Thread(target=self.done_thread, args=('Backup',), name="Done thread")
            dt.setDaemon(True)
            dt.start()

            # Process data buckets
            for bucket_name in bucket_list:
                try:
                    collection = self.datastore.get_collection(bucket_name)
                    for item in collection.stream_search(query, fl="id", item_buffer_size=500, as_obj=False):
                        self.worker_queue.push({"bucket_name": bucket_name, "key": item['id'],
                                                "follow_keys": follow_keys})

                except Exception as e:
                    self.cleanup()
                    if self.logger:
                        self.logger.execption(e)
                        self.logger.error("Error occurred while processing bucket %s." % bucket_name)
                    self.bucket_error.append(bucket_name)

            for _ in range(self.worker_count):
                self.worker_queue.push({"stop": True})

            dt.join()
        except Exception as e:
            if self.logger:
                self.logger.execption(e)

    def restore(self):
        try:
            if self.logger:
                self.logger.info("\n------------------------")
                self.logger.info("----- Data Restore -----")
                self.logger.info("------------------------")
                self.logger.info(f"    Workers: {self.worker_count}")
                self.logger.info(f"    Target directory: {self.working_dir}")

            for x in range(self.worker_count):
                if self.use_threading:
                    t = threading.Thread(target=restore_worker,
                                         args=(x, self.instance_id, self.working_dir))
                    t.setDaemon(True)
                    t.start()
                else:
                    p = Process(target=restore_worker, args=(x, self.instance_id, self.working_dir))
                    p.start()
                    self.plist.append(p)

            # Start done thread
            dt = threading.Thread(target=self.done_thread, args=('Restore',), name="Done thread")
            dt.setDaemon(True)
            dt.start()

            # Wait for workers to finish
            dt.join()
        except Exception as e:
            if self.logger:
                self.logger.execption(e)


def _string_getter(data):
    if data is not None:
        return [data]
    else:
        return []


def _result_getter(data):
    if data is not None:
        return [x for x in data if not x.endswith('.e')]
    else:
        return []


def _emptyresult_getter(data):
    if data is not None:
        return [x for x in data if x.endswith('.e')]
    else:
        return []


def _error_getter(data):
    if data is not None:
        return [x for x in data if x.rsplit('.e', 1)[1] not in ERROR_TYPES.values()]
    else:
        return []


def _sha256_getter(data):
    if data is not None:
        return [x[:64] for x in data]
    else:
        return []


def _file_getter(data):
    if data is not None:
        return [x['sha256'] for x in data]
    else:
        return []


def _result_file_getter(data):
    if data is not None:
        supp = data.get("supplementary", []) + data.get("extracted", [])
        return _file_getter(supp)
    else:
        return []


FOLLOW_KEYS = {
    "alert": [
        ('submission', 'sid', _string_getter),
    ],
    "submission": [
        ('result', 'results', _result_getter),
        ('error', 'errors', _error_getter),
        ('file', 'results', _sha256_getter),
        ('file', 'files', _file_getter),
        ('file', 'errors', _sha256_getter),
    ],
    "results": [
        ('file', 'response', _result_file_getter),
    ]
}
