
hostname = 'unknownhost'
# noinspection PyBroadException
try:
    from assemblyline.common.net import get_hostname
    hostname = get_hostname()
except:  # pylint:disable=W0702
    pass

ip = 'x.x.x.x'
# noinspection PyBroadException
try:
    from assemblyline.common.net import get_hostip
    ip = get_hostip()
except Exception:  # pylint:disable=W0702
    pass

AL_SYSLOG_FORMAT = f'{ip} AL %(levelname)8s %(process)5d %(name)20s | %(message)s'
AL_LOG_FORMAT = f'%(asctime)-16s %(levelname)8s {hostname} %(process)d %(name)30s | %(message)s'
AL_JSON_FORMAT = f'{{"timestamp": "%(asctime)s", "type": "assemblyline_log", "ip": "{ip}", "ip": "{hostname}", ' \
    f'"level": "%(levelname)s", "pid": "%(process)d", "name": "%(name)s", "message": "%(message)s"}}'