import logging
import logging.config
import logging.handlers
from traceback import format_exception

import json
import os
from typing import Optional

from assemblyline.common import forge
from assemblyline.common.logformat import AL_LOG_FORMAT, AL_SYSLOG_FORMAT, AL_JSON_FORMAT
from assemblyline.odm.models.config import Config

log_level_map = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "DISABLED": 60
}


class JsonFormatter(logging.Formatter):
    def formatMessage(self, record):
        if record.exc_info:
            record.exc_text = self.formatException(record.exc_info)
            record.exc_info = None

        if record.exc_text:
            record.message += '\n' + record.exc_text
            record.exc_text = None

        record.message = json.dumps(record.message)
        return self._style.format(record)

    def formatException(self, exc_info):
        return ''.join(format_exception(*exc_info))


def init_logging(name: str, config: Optional[Config] = None, log_level=None):
    logger = logging.getLogger('assemblyline')

    # Test if we've initialized the log handler already.
    if len(logger.handlers) != 0:
        return

    if name.startswith("assemblyline."):
        name = name[13:]

    if config is None:
        config = forge.get_config()

    if log_level is None:
        log_level = log_level_map[config.logging.log_level]

    logging.root.setLevel(logging.CRITICAL)
    logger.setLevel(log_level)

    if config.logging.log_level == "DISABLED":
        # While log_level is set to disable, we will not create any handlers
        return

    if config.logging.log_to_file:
        if not os.path.isdir(config.logging.log_directory):
            print('Warning: log directory does not exist. Will try to create %s' % config.logging.log_directory)
            os.makedirs(config.logging.directory)

        if log_level <= logging.DEBUG:
            dbg_file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(config.logging.log_directory, f'{name}.dbg'), maxBytes=10485760, backupCount=5)
            dbg_file_handler.setLevel(logging.DEBUG)
            if config.logging.log_as_json:
                dbg_file_handler.setFormatter(JsonFormatter(AL_JSON_FORMAT))
            else:
                dbg_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
            logger.addHandler(dbg_file_handler)

        if log_level <= logging.INFO:
            op_file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(config.logging.log_directory, f'{name}.log'), maxBytes=10485760, backupCount=5)
            op_file_handler.setLevel(logging.INFO)
            if config.logging.log_as_json:
                op_file_handler.setFormatter(JsonFormatter(AL_JSON_FORMAT))
            else:
                op_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
            logger.addHandler(op_file_handler)

        if log_level <= logging.ERROR:
            err_file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(config.logging.log_directory, f'{name}.err'), maxBytes=10485760, backupCount=5)
            err_file_handler.setLevel(logging.ERROR)
            if config.logging.log_as_json:
                err_file_handler.setFormatter(JsonFormatter(AL_JSON_FORMAT))
            else:
                err_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
            err_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
            logger.addHandler(err_file_handler)
 
    if config.logging.log_to_console:
        console = logging.StreamHandler()
        if config.logging.log_as_json:
            console.setFormatter(JsonFormatter(AL_JSON_FORMAT))
        else:
            console.setFormatter(logging.Formatter(AL_LOG_FORMAT))
        logger.addHandler(console)

    if config.logging.log_to_syslog and config.logging.syslog_host and config.logging_port:
        syslog_handler = logging.handlers.SysLogHandler(address=(config.logging.syslog_host,
                                                                 config.logging.syslog_port))
        syslog_handler.formatter = logging.Formatter(AL_SYSLOG_FORMAT)
        logger.addHandler(syslog_handler)
