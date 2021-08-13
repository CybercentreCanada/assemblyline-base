"""
A base classes and utilities to provide a common set of behaviours for
the assemblyline core server nodes.
"""
import enum
import functools
import time
import threading
import logging
import signal
import sys
import io
import os
from typing import cast, Dict, Callable

from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.odm.models.service import Service
from assemblyline.common import forge, log as al_log


SHUTDOWN_SECONDS_LIMIT = 10

# Don't write to the heartbeat file if it hasn't been at least this many seconds since the last write.
HEARTBEAT_TIME_LIMIT = 3


class ServerBase(threading.Thread):
    """Utility class for Assemblyline server processes.

    Inheriting from thread so that the main work is done off the main thread.
    This lets the main thread handle interrupts properly, even when the workload
    makes a blocking call that would normally stop this.
    """
    def __init__(self, component_name: str, logger: logging.Logger = None,
                 shutdown_timeout: float = SHUTDOWN_SECONDS_LIMIT, config=None):
        super().__init__(name=component_name)
        al_log.init_logging(component_name)
        self.config = config or forge.get_config()

        self.running = None
        self.stopping = threading.Event()

        self.log = logger or logging.getLogger(component_name)
        self._exception = None
        self._traceback = None
        self._shutdown_timeout = shutdown_timeout if shutdown_timeout is not None else SHUTDOWN_SECONDS_LIMIT
        self._old_sigint = None
        self._old_sigterm = None
        self._stopped = False
        self._last_heartbeat = 0

    def __enter__(self):
        self.log.info(f"Initialized")
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        if _exc_type is not None:
            self.log.exception(f'Terminated because of an {_exc_type} exception')
        else:
            self.log.info(f'Terminated')

    def __stop(self):
        """Hard stop, can still be blocked in some cases, but we should try to avoid them."""
        time.sleep(self._shutdown_timeout)
        self.log.error(f"Server {self.__class__.__name__} has shutdown hard after waiting {self._shutdown_timeout} seconds to stop")

        if not self._stopped:
            self._stopped = True
            exit(1)  # So any static analysis tools get the behaviour of this function 'correct'
        import ctypes
        ctypes.string_at(0)  # SEGFAULT out of here

    def interrupt_handler(self, signum, stack_frame):
        self.log.info(f"Instance caught signal. Coming down...")
        self.stop()
        if signum == signal.SIGINT and self._old_sigint:
            self._old_sigint(signum, stack_frame)
        if signum == signal.SIGTERM and self._old_sigterm:
            self._old_sigterm(signum, stack_frame)

    def raising_join(self):
        self.join()
        if self._traceback and self._exception:
            raise self._exception.with_traceback(self._traceback)

    # noinspection PyBroadException
    def run(self):
        try:
            self.try_run()
        except Exception:
            _, self._exception, self._traceback = sys.exc_info()
            self.log.exception("Exiting:")

    def sleep(self, timeout):
        self.stopping.wait(timeout)
        return self.running
        
    def serve_forever(self):
        self.start()
        # We may not want to let the main thread block on a single join call. 
        # It can interfere with signal handling.
        while self.sleep(1):
            pass

    def start(self):
        """Start the server workload."""
        self.running = True
        super().start()
        self.log.info(f"Started")
        self._old_sigint = signal.signal(signal.SIGINT, self.interrupt_handler)
        self._old_sigterm = signal.signal(signal.SIGTERM, self.interrupt_handler)

    def stop(self):
        """Ask nicely for the server to stop.

        After a timeout, a hard stop will be triggered.
        """
        # The running loops should stop within a few seconds of this flag being set.
        self.running = False
        self.stopping.set()

        # If it doesn't stop within a few seconds, this other thread should kill the entire process
        stop_thread = threading.Thread(target=self.__stop)
        stop_thread.daemon = True
        stop_thread.start()

    def try_run(self):
        pass

    def heartbeat(self, timestamp: int = None):
        """Touch a special file on disk to indicate this service is responsive.

        This should be called in the main processing loop of a component, calling it in
        a background thread defeats the purpose. Ideally it should be called at least a couple
        times a minute.
        """
        if timestamp is not None:
            timestamp = (timestamp, timestamp)

        if self.config.logging.heartbeat_file:
            # Only do the heartbeat every few seconds at most. If a fast component is
            # calling this for every message processed we don't want to slow it down
            # by doing a "disk" system call every few milliseconds
            now = time.time()
            if now - self._last_heartbeat < HEARTBEAT_TIME_LIMIT:
                return
            self._last_heartbeat = now
            with io.open(self.config.logging.heartbeat_file, 'ab'):
                os.utime(self.config.logging.heartbeat_file, times=timestamp)

    def sleep_with_heartbeat(self, duration):
        """Sleep while calling heartbeat periodically."""
        while duration > 0:
            self.heartbeat()
            sleep_time = min(duration, HEARTBEAT_TIME_LIMIT * 2)
            self.sleep(sleep_time)
            duration -= sleep_time


# This table in redis tells us about the current stage of operation a service is in.
# This is complementary to the 'enabled' flag in the service spec.
# If the service is marked as enabled=true, each component should take steps needed to move it to the 'Running' stage.
# If the service is marked as enabled=false, each component should take steps needed to stop it.
class ServiceStage(enum.IntEnum):
    # A service is not running
    # - if enabled scaler will start dependent containers and move to next stage
    Off = 0
    # A service is not running, but dependencies have been started
    # - if enabled updater will try to
    Update = 1
    # At this stage scaler will begin
    Running = 2
    Paused = 3

    # If at any time a service is disabled, scaler will stop the dependent containers


def get_service_stage_hash(redis):
    """A hash from service name to ServiceStage enum values."""
    return Hash('service-stage', redis)


class CoreBase(ServerBase):
    """Expands the basic server setup in server base with some initialization steps most core servers take."""

    def __init__(self, component_name: str, logger: logging.Logger = None,
                 shutdown_timeout: float = None, config=None, datastore=None,
                 redis=None, redis_persist=None):
        super().__init__(component_name=component_name, logger=logger, shutdown_timeout=shutdown_timeout, config=config)
        self.datastore = datastore or forge.get_datastore(self.config)

        # Connect to all of our persistent redis structures
        self.redis = redis or get_client(
            host=self.config.core.redis.nonpersistent.host,
            port=self.config.core.redis.nonpersistent.port,
            private=False,
        )
        self.redis_persist = redis_persist or get_client(
            host=self.config.core.redis.persistent.host,
            port=self.config.core.redis.persistent.port,
            private=False,
        )

        # Create a cached service data object, and access to the service status
        self.service_info = cast(Dict[str, Service], forge.CachedObject(self._get_services))
        self._service_stage_hash = get_service_stage_hash(self.redis)

    def _get_services(self):
        # noinspection PyUnresolvedReferences
        return {x.name: x for x in self.datastore.list_all_services(full=True)}

    def get_service_stage(self, service_name: str) -> ServiceStage:
        return ServiceStage(self._service_stage_hash.get(service_name) or ServiceStage.Off)


class ThreadedCoreBase(CoreBase):
    def __init__(self, component_name: str, logger: logging.Logger = None,
                 shutdown_timeout: float = None, config=None, datastore=None,
                 redis=None, redis_persist=None):
        super().__init__(component_name=component_name, logger=logger, shutdown_timeout=shutdown_timeout,
                         config=config, datastore=datastore, redis=redis, redis_persist=redis_persist)

        # Thread events related to exiting
        self.main_loop_exit = threading.Event()

    def stop(self):
        super().stop()
        self.main_loop_exit.wait(30)

    def log_crashes(self, fn):
        @functools.wraps(fn)
        def with_logs(*args, **kwargs):
            # noinspection PyBroadException
            try:
                fn(*args, **kwargs)
            except Exception:
                self.log.exception(f'Crash in dispatcher: {fn.__name__}')
        return with_logs

    def maintain_threads(self, expected_threads: Dict[str, Callable]):
        expected_threads = {name: self.log_crashes(start) for name, start in expected_threads.items()}
        threads = {}

        # Run as long as we need to
        while self.running:
            # Check for any crashed threads
            for name, thread in list(threads.items()):
                if not thread.is_alive():
                    self.log.warning(f'Restarting thread: {name}')
                    threads.pop(name)

            # Start any missing threads
            for name, function in expected_threads.items():
                if name not in threads:
                    self.log.info(f'Starting thread: {name}')
                    threads[name] = thread = threading.Thread(target=function, name=name)
                    thread.start()

            # Take a break before doing it again
            super().heartbeat()
            self.sleep(2)

        for _t in threads.values():
            _t.join()

        self.main_loop_exit.set()
