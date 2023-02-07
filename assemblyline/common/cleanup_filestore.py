"""
Helper functions for the CLI to use in garbage collecting the filestore.
"""
from __future__ import annotations
import multiprocessing
import ctypes
from queue import Empty

from assemblyline.common.forge import get_datastore
from assemblyline.filestore import create_transport
from assemblyline.datastore.collection import Index


FILTER_WORKERS = 8
DELETE_WORKERS = 8


def list_files(transport_url: str, listing_running, listed_queue, listing_count):
    """"A worker that feeds a queue with all the files listed by a filestore."""
    total_listed = 0
    try:
        # Connect to the transport and send the file names, count how many are sent
        transport = create_transport(transport_url)
        for filename in transport.list():
            total_listed += 1
            listed_queue.put(filename)
    finally:
        # Save the number sent to shared memory for other processes to read
        with listing_count.get_lock():
            listing_count.value = total_listed
        # Mark in shared memory that this worker is terminating
        with listing_running.get_lock():
            listing_running.value = 0


def filter_files(listing_running, listed_queue, filtering_running, filtered_queue, filtering_count):
    """
    A worker that reads the listed files, and filters out those that have
    entries in the file or cached_file indices of the database.

    Files without entries are fed into an output queue.
    """
    total_filtered = 0
    try:
        datastore = get_datastore(archive_access=True)
        while True:
            # Get a filename from the listing worker
            try:
                filename = listed_queue.get(timeout=3)
            except Empty:
                # If the queue is empty, check if the listing worker is finished
                with listing_running.get_lock():
                    if listing_running.value == 0:
                        break
                continue

            # Check if the file exists in the file index
            if datastore.file.get_if_exists(filename, index_type=Index.HOT_AND_ARCHIVE):
                total_filtered += 1
                continue

            # Check if the file exists in the cached file index
            if datastore.cached_file.get_if_exists(filename, index_type=Index.HOT_AND_ARCHIVE):
                total_filtered += 1
                continue

            # File has no records in datastore, feed to erase worker
            filtered_queue.put(filename)
    finally:
        # Add the number of files processed by this worker to a shared memory value
        with filtering_count.get_lock():
            filtering_count.value += total_filtered
        # Decrease the counter of running filter workers to account for this worker
        # exiting.
        with filtering_running.get_lock():
            filtering_running.value -= 1


def erase_files(transport_url, filtering_running, filtered_queue, erase_count):
    """
    A worker that reads from the filtered files queue and erases the
    specified files from the filestore.
    """
    total_erased = 0
    try:
        transport = create_transport(transport_url)
        while True:
            # Read files from the filtered file queue, exit if no more filter
            # workers are running
            try:
                filename = filtered_queue.get(timeout=3)
            except Empty:
                with filtering_running.get_lock():
                    if filtering_running.value == 0:
                        break
                continue

            # Erase the file fed to this worker
            transport.delete(filename)
            total_erased += 1
    finally:
        # Add the number of files erased by this worker to a shared memory worker
        with erase_count.get_lock():
            erase_count.value += total_erased


def cleanup_filestore(transport_url: str) -> str:
    # Create and initialize shared memory values and queues to communicate between the workers
    listing_count = multiprocessing.Value(ctypes.c_ulonglong)
    listing_count.value = 0
    listing_running = multiprocessing.Value(ctypes.c_ulonglong)
    listing_running.value = 1
    listed_queue = multiprocessing.Queue(10000)

    filtering_count = multiprocessing.Value(ctypes.c_ulonglong)
    filtering_count.value = 0
    filtering_running = multiprocessing.Value(ctypes.c_ulonglong)
    filtering_running.value = FILTER_WORKERS
    filtered_queue = multiprocessing.Queue(50000)

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
        for _ in range(DELETE_WORKERS)
    ]
    for _f in erase_workers:
        _f.start()

    # Wait for work to finish in order
    listing_worker.join()
    for _f in filter_workers:
        _f.join()
    for _f in erase_workers:
        _f.join()

    # Return a status string for the CLI
    return f'Files listed: {listing_count.value:,}; filtered: {filtering_count.value:,}; erased: {erase_count.value:,}'
