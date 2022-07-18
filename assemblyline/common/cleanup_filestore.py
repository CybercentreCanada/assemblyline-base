import multiprocessing
import ctypes
from queue import Empty

from assemblyline.common.forge import get_datastore
from assemblyline.filestore import create_transport


FILTER_WORKERS = 8
DELETE_WORKERS = 8


def list_files(transport_url: str, listing_running, listed_queue: multiprocessing.Queue[str], listing_count):
    total_listed = 0
    try:
        transport = create_transport(transport_url)
        for filename in transport.list():
            total_listed += 1
            listed_queue.put(filename)
    finally:
        with listing_count.get_lock():
            listing_count.value = total_listed
        with listing_running.get_lock():
            listing_running.value = 0


def filter_files(listing_running, listed_queue, filtering_running, filtered_queue, filtering_count):
    total_filtered = 0
    try:
        datastore = get_datastore(archive_access=True)
        while True:
            try:
                filename = listed_queue.get(timeout=3)
            except Empty:
                with listing_running.get_lock():
                    if listing_running.value == 0:
                        break
                continue

            if datastore.file.get_if_exists(filename, archive_access=True):
                total_filtered += 1
                continue

            if datastore.cached_file.get_if_exists(filename, archive_access=True):
                total_filtered += 1
                continue

            filtered_queue.put(filename)
    finally:
        with filtering_count.get_lock():
            filtering_count.value += total_filtered
        with filtering_running.get_lock():
            filtering_running.value -= 1


def erase_files(transport_url, filtering_running, filtered_queue, erase_count):
    total_erased = 0
    try:
        transport = create_transport(transport_url)
        while True:
            try:
                filename = filtered_queue.get(timeout=3)
            except Empty:
                with filtering_running.get_lock():
                    if filtering_running.value == 0:
                        break
                continue

            transport.delete(filename)
            total_erased += 1
    finally:
        with erase_count.get_lock():
            erase_count.value += total_erased


def cleanup_filestore(transport_url: str) -> str:
    listing_count = multiprocessing.Value(ctypes.c_ulonglong)
    listing_count.value = 0
    listing_running = multiprocessing.Value(ctypes.c_ulonglong)
    listing_running.value = 1
    listed_queue: multiprocessing.Queue[str] = multiprocessing.Queue(10000)

    filtering_count = multiprocessing.Value(ctypes.c_ulonglong)
    filtering_count.value = 0
    filtering_running = multiprocessing.Value(ctypes.c_ulonglong)
    filtering_running.value = FILTER_WORKERS
    filtered_queue: multiprocessing.Queue[str] = multiprocessing.Queue(50000)

    erase_count = multiprocessing.Value(ctypes.c_ulonglong)
    erase_count.value = 0

    # Spawn process to list files
    listing_worker = multiprocessing.Process(
        target=list_files,
        args=(transport_url, listing_running, listed_queue, listing_count),
        daemon=True
    )
    listing_worker.start()

    # Spawn workers to filter file names
    filter_workers = [
        multiprocessing.Process(
            target=filter_files,
            args=(listing_running, listed_queue, filtering_running, filtered_queue, filtering_count),
            daemon=True
        )
        for _ in range(FILTER_WORKERS)
    ]
    for _f in filter_workers:
        _f.start()

    # Spawn workers to erase files
    erase_workers = [
        multiprocessing.Process(
            target=erase_files,
            args=(transport_url, filtering_running, filtered_queue, erase_count),
            daemon=True
        )
        for _ in range(FILTER_WORKERS)
    ]
    for _f in erase_workers:
        _f.start()

    # Wait for work to finish in order
    listing_worker.join()
    for _f in filter_workers:
        _f.join()
    for _f in erase_workers:
        _f.join()

    return f'Files listed: {listing_count.value:,}; filtered: {filtering_count.value:,}; erased: {erase_count.value:,}'
