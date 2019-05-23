
import json
import time
import os
import subprocess
import threading

from multiprocessing import Process

from assemblyline.common import forge
from assemblyline.common.uid import get_random_id
from assemblyline.odm.models.error import ERROR_TYPES
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.queues.named import NamedQueue


# noinspection PyBroadException
def backup_worker(worker_id, instance_id, working_dir):
    datastore = forge.get_datastore()
    worker_queue = NamedQueue(f"r-worker-{instance_id}", ttl=1800)
    done_queue = NamedQueue(f"r-done-{instance_id}", ttl=1800)
    hash_queue = Hash(f"r-hash-{instance_id}")
    with open(os.path.join(working_dir, "backup.part%s" % worker_id), "w+") as backup_file:
        while True:
            data = worker_queue.pop()

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


class DistributedBackup(object):
    def __init__(self, working_dir, worker_count=50, spawn_workers=True):
        self.working_dir = working_dir
        if os.path.exists(self.working_dir):
            raise ValueError("Working directory already exists")
        os.makedirs(self.working_dir, exist_ok=True)
        self.datastore = forge.get_datastore()
        self.plist = []
        self.instance_id = get_random_id()
        self.worker_queue = NamedQueue(f"r-worker-{self.instance_id}", ttl=1800)
        self.done_queue = NamedQueue(f"r-done-{self.instance_id}", ttl=1800)
        self.hash_queue = Hash(f"r-hash-{self.instance_id}")
        self.bucket_error = []
        self.VALID_BUCKETS = sorted(list(self.datastore.ds.get_models().keys()))
        self.worker_count = worker_count
        self.spawn_workers = spawn_workers
        self.total_count = 0
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

        while True:
            msg = self.done_queue.pop(timeout=5)

            if msg is None and self.worker_queue.length() == 0:
                break

            if msg.get('success', False):
                self.total_count += 1

                bucket_name = msg['bucket_name']

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
                    print("%s (%s at %s keys/sec) ==> %s" %
                          (self.total_count,
                           new_t - self.last_time,
                           int((self.total_count - self.last_count) / (new_t - self.last_time)),
                           self.map_count))
                    self.last_count = self.total_count
                    self.last_time = new_t
            else:
                self.error_count += 1

        # Cleanup
        self.cleanup()

        summary = ""
        summary += f"{title} DONE! (%s items - %s errors - %s secs)\n" % \
                   (self.total_count, self.error_count, time.time() - t0)
        summary += "\n############################################\n"
        summary += f"##########  {title.upper()} SUMMARY  ################\n"
        summary += "############################################\n\n"

        for k, v in self.map_count.items():
            summary += "\t%15s: %s\n" % (k.upper(), v)

        if len(self.missing_map_count.keys()) > 0:
            summary += "\n\nMissing data:\n\n"
            for k, v in self.missing_map_count.items():
                summary += "\t%15s: %s\n" % (k.upper(), v)

        if len(self.bucket_error) > 0:
            summary += f"\nThese buckets failed to {title.lower()} completely: {self.bucket_error}\n"
        print(summary)

    # noinspection PyBroadException,PyProtectedMember
    def backup(self, bucket_list, follow_keys=False, query=None):
        if query is None:
            query = 'id:*'

        for bucket in bucket_list:
            if bucket not in self.VALID_BUCKETS:
                print("\n%s is not a valid bucket.\n\nThe list of valid buckets is the following:\n\n\t%s\n" %
                      (bucket.upper(), "\n\t".join(self.VALID_BUCKETS)))
                return

        try:
            print(f"Launching {self.worker_count} backup workers...")
            for x in range(self.worker_count):
                p = Process(target=backup_worker, args=(x, self.instance_id, self.working_dir))
                p.start()
                self.plist.append(p)

            print("Starting completion thread...")
            # Start done thread
            dt = threading.Thread(target=self.done_thread, args=('Backup',), name="Done thread")
            dt.setDaemon(True)
            dt.start()

            # Process data buckets
            print("Send all keys of buckets [%s] to be backed-up..." % ', '.join(bucket_list))
            if follow_keys:
                print("Distributed backup will perform a deep backup.")
            for bucket_name in bucket_list:
                try:
                    collection = self.datastore.get_collection(bucket_name)
                    for item in collection.stream_search(query, fl="id", item_buffer_size=500, as_obj=False):
                        self.worker_queue.push({"bucket_name": bucket_name, "key": item['id'],
                                                "follow_keys": follow_keys})

                except Exception as e:
                    self.cleanup()
                    print(e)
                    print("Error occurred while processing bucket %s." % bucket_name)
                    self.bucket_error.append(bucket_name)

            dt.join()
        except Exception as e:
            print(e)
        finally:
            print("Backup of %s terminated.\n" % ", ".join(bucket_list))

    # noinspection PyUnresolvedReferences
    def restore_execution(self):
        with open(os.path.join(self.working_dir, "backup.part%s" % self.worker_id), "rb") as input_file:
            for l in input_file.xreadlines():
                bucket_name, key, data = json.loads(l)

                success = True
                try:
                    v = self.ds.sanitize(bucket_name, data, key)
                    self.ds._save_bucket_item(self.ds.get_bucket(bucket_name), key, v)
                except Exception:
                    success = False

                self.done_queue.push({"is_done": False,
                                      "success": success,
                                      "missing": False,
                                      "bucket_name": bucket_name,
                                      "key": key})

    def restore(self):
        try:
            # Spawning workers
            print("Spawning %s restore workers ..." % self.worker_count)
            subproc_logfile = self.working_dir.rstrip("/") + ".log"
            subproc_logfile_fh = open(subproc_logfile, 'wb')
            for x in range(self.worker_count):
                run_dir = __file__[:__file__.index("common/")]
                p = subprocess.Popen([os.path.join(run_dir, "run", "invoke.sh"),
                                      os.path.join(run_dir, "run", "distributed_worker.py"),
                                      str(TYPE_RESTORE),
                                      str(x),
                                      self.instance_id,
                                      self.working_dir],
                                     stderr=subproc_logfile_fh,
                                     stdout=subproc_logfile_fh)
                self.plist.append(p)
            print("All restore workers started, waiting for them to import all the data...")
            print("stdout/stderr from child processes will be written to %s" % subproc_logfile)

            # Start done thread
            t = threading.Thread(target=self._done_thread, args=(TYPE_RESTORE,), name="Done thread")
            t.setDaemon(True)
            t.start()

            # Wait for workers to finish
            t.join()
        except Exception as e:
            print(e)
        finally:
            print("Restore of backup in %s terminated.\n" % self.working_dir)


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


# noinspection PyProtectedMember,PyBroadException
class BackupWorker(object):
    def __init__(self, wid, worker_type, working_dir, instance_id):
        self.working_dir = working_dir
        self.worker_id = wid
        self.ds = forge.get_datastore()
        self.worker_type = worker_type
        self.instance_id = instance_id

        if worker_type == TYPE_BACKUP:
            self.hash_queue = Hash("r-hash_%s" % self.instance_id, db=DATABASE_NUM)
            self.follow_queue = NamedQueue("r-follow_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
            self.queue = NamedQueue("r-backup_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
            self.done_queue = NamedQueue("r-backup-done_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)
        else:
            self.hash_queue = None
            self.follow_queue = None
            self.queue = None
            self.done_queue = NamedQueue("r-restore-done_%s" % self.instance_id, db=DATABASE_NUM, ttl=1800)

    def _backup(self):
        done = False
        current_queue = self.queue
        with open(os.path.join(self.working_dir, "backup.part%s" % self.worker_id), "wb") as backup_file:
            while True:
                data = current_queue.pop(timeout=1)
                if not data and done:
                    break
                elif not data:
                    continue

                if isinstance(data, list):
                    data = data[0]

                if data.get('is_done', False) and not done:
                    current_queue = self.follow_queue
                    done = True
                    continue
                elif data.get('is_done', False) and done:
                    # Go someone else done message. Push it back on the queue and sleep...
                    self.queue.push({"is_done": True})
                    time.sleep(1)
                    continue

                missing = False
                success = True
                try:
                    to_write = self.ds._get_bucket_item(self.ds.get_bucket(data['bucket_name']), data['key'])
                    if to_write:
                        if data.get('follow_keys', False):
                            for bucket, bucket_key, getter in FOLLOW_KEYS.get(data['bucket_name'], []):
                                for key in getter(to_write.get(bucket_key, None)):
                                    hash_key = "%s_%s" % (bucket, key)
                                    if not self.hash_queue.exists(hash_key):
                                        self.hash_queue.add(hash_key, "True")
                                        self.follow_queue.push({"bucket_name": bucket, "key": key, "follow_keys": True})

                        backup_file.write(json.dumps((data['bucket_name'], data['key'], to_write)) + "\n")
                    else:
                        missing = True

                except Exception:
                    success = False

                self.done_queue.push({"is_done": False,
                                      "success": success,
                                      "missing": missing,
                                      "bucket_name": data['bucket_name'],
                                      "key": data['key']})

    # noinspection PyUnresolvedReferences
    def _restore(self):
        with open(os.path.join(self.working_dir, "backup.part%s" % self.worker_id), "rb") as input_file:
            for l in input_file.xreadlines():
                bucket_name, key, data = json.loads(l)

                success = True
                try:
                    v = self.ds.sanitize(bucket_name, data, key)
                    self.ds._save_bucket_item(self.ds.get_bucket(bucket_name), key, v)
                except Exception:
                    success = False

                self.done_queue.push({"is_done": False,
                                      "success": success,
                                      "missing": False,
                                      "bucket_name": bucket_name,
                                      "key": key})

    def run(self):
        if self.worker_type == TYPE_BACKUP:
            self._backup()
        else:
            self._restore()

        self.done_queue.push({"is_done": True})


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Argument must be single backup to restore")
        exit(1)

    backup = sys.argv[1]
    backup_manager = DistributedBackup(backup, worker_count=1, spawn_workers=False)
    backup_manager.restore()