import logging
import logging.handlers
import logging.config
import os

from assemblyline.common.logformat import AL_LOG_FORMAT, AL_SYSLOG_FORMAT
from assemblyline.common import forge


def init_logging(name, config=None, log_level=logging.INFO):
    logger = logging.getLogger('assemblyline')

    # Test if we've initialized the log handler already.
    if len(logger.handlers) != 0:
        return

    if name.startswith("assemblyline."):
        name = name[13:]

    if config is None:
        config = forge.get_config()

    logging.root.setLevel(logging.CRITICAL)
    logger.setLevel(log_level)

    if config.logging.log_to_file:
        if not os.path.isdir(config.logging.log_directory):
            print('Warning: log directory does not exist. Will try to create %s' % config.logging.log_directory)
            os.makedirs(config.logging.directory)

        if log_level == logging.DEBUG:
            dbg_file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(config.logging.log_directory, f'{name}.dbg'), maxBytes=10485760, backupCount=5)
            dbg_file_handler.setLevel(logging.DEBUG)
            dbg_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
            logger.addHandler(dbg_file_handler)

        op_file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(config.logging.log_directory, f'{name}.log'), maxBytes=10485760, backupCount=5)
        op_file_handler.setLevel(logging.INFO)
        op_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
        logger.addHandler(op_file_handler)

        err_file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(config.logging.log_directory, f'{name}.err'), maxBytes=10485760, backupCount=5)
        err_file_handler.setLevel(logging.ERROR)
        err_file_handler.setFormatter(logging.Formatter(AL_LOG_FORMAT))
        logger.addHandler(err_file_handler)
 
    if config.logging.log_to_console:
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(AL_LOG_FORMAT))
        logger.addHandler(console)

    if config.logging.log_to_syslog and config.logging.syslog_host:
        syslog_handler = logging.handlers.SysLogHandler(address=(config.logging.syslog_host, 514))
        syslog_handler.formatter = logging.Formatter(AL_SYSLOG_FORMAT)
        logger.addHandler(syslog_handler)
