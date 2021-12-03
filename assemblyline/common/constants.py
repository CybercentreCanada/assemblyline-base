import enum
import os
from assemblyline.common.path import modulepath


SUBMISSION_QUEUE = 'dispatch-submission-queue'
DISPATCH_TASK_HASH = 'dispatch-active-submissions'
DISPATCH_RUNNING_TASK_HASH = 'dispatch-active-tasks'
SCALER_TIMEOUT_QUEUE = 'scaler-timeout-queue'


# Some pure functions for getting queue lengths (effectively for appending/prepending constants to strings)
def service_queue_name(service: str) -> str:
    """Take the name of a service, and provide the queue name to send tasks to that service."""
    return 'service-queue-' + service


def make_watcher_list_name(sid: str) -> str:
    """Get the name of the list dispatcher will pull for sending out submission events."""
    return 'dispatch-watcher-list-' + sid


def get_temporary_submission_data_name(sid: str, file_hash: str) -> str:
    """The HashMap used for tracking auxiliary processing data."""
    return '/'.join((sid, file_hash, 'temp_data'))


def get_tag_set_name(sid: str, file_hash: str) -> str:
    """The HashSet used to track the tags for an in-process file."""
    return '/'.join((sid, file_hash, 'tags'))


# A table storing information about the state of a service, expected type is ExpiringHash
# with a default ttl of None, and the ttl set per field based on the timeouts of queries
# and service operation
class ServiceStatus(enum.IntEnum):
    Idle = 0
    Running = 1


SERVICE_STATE_HASH = 'service-stasis-table'

# A null empty accepts, accepts all. A null rejects, rejects nothing
DEFAULT_SERVICE_ACCEPTS = ".*"
DEFAULT_SERVICE_REJECTS = "empty|metadata/.*"

# Queue priority values for each bucket in the ingester
PRIORITIES = {
    'low': 100,  # 0 -> 100
    'medium': 200,  # 101 -> 200
    'high': 300,
    'critical': 400,
    'user-low': 500,
    'user-medium': 1000,
    'user-high': 1500
}
MAX_PRIORITY = 2000

# The above priority values presented as a range for consistency
PRIORITY_RANGES = {}
_start = -1
for _end, _level in sorted((val, key) for key, val in PRIORITIES.items()):
    PRIORITY_RANGES[_level] = (_start + 1, _end)
    _start = _end


# Score thresholds for determining which queue priority a reingested item
# gets based on its previous score.
# eg.: item with a previous score of 99 will get 'low' priority
#      item with a previous score of 300 will get a 'high' priority
PRIORITY_THRESHOLDS = {
    'critical': 500,
    'high': 100,
}

RECOGNIZED_TYPES = {
    'android/apk': True,
    'android/dex': True,
    'android/resource': True,
    'android/xml': True,
    'archive/7-zip': True,
    'archive/ace': True,
    'archive/ar': True,
    'archive/audiovisual/flash': True,
    'archive/bzip2': True,
    'archive/cabinet': True,
    'archive/cart': True,
    'archive/chm': True,
    'archive/cpio': True,
    'archive/gzip': True,
    'archive/iso': True,
    'archive/lzma': True,
    'archive/rar': True,
    'archive/tar': True,
    'archive/tnef': True,
    'archive/unknown': True,
    'archive/xz': True,
    'archive/zip': True,
    'audiovisual/afs': True,
    'audiovisual/acb': True,
    'audiovisual/flash': True,
    'audiovisual/fsb': True,
    'audiovisual/unknown': True,
    'certificate/rsa': True,
    'code/animation/ccb': True,
    'code/autorun': True,
    'code/batch': True,
    'code/c': True,
    'code/css': True,
    'code/csharp': True,
    'code/erlang': True,
    'code/gles': True,
    'code/glsl': True,
    'code/go': True,
    'code/hta': True,
    'code/html': True,
    'code/java': True,
    'code/javascript': True,
    'code/jscript': True,
    'code/ida': True,
    'code/lisp': True,
    'code/nu': True,
    'code/pdfjs': True,
    'code/perl': True,
    'code/php': True,
    'code/ps1': True,
    'code/python': True,
    'code/ruby': True,
    'code/rust': True,
    'code/shell': True,
    'code/sgml': True,
    'code/sql': True,
    'code/vbe': True,
    'code/vbs': True,
    'code/wsf': True,
    'code/xml': True,
    'db/dbf': True,
    'db/sqlite': True,
    'document/installer/windows': True,
    'document/office/equation': True,
    'document/office/excel': True,
    'document/office/email': True,
    'document/office/hwp': True,
    'document/office/mhtml': True,
    'document/office/paintbrush': True,
    'document/office/package': True,
    'document/office/powerpoint': True,
    'document/office/passwordprotected': True,
    'document/office/ole': True,
    'document/office/onenote': True,
    'document/office/rtf': True,
    'document/office/unknown': True,
    'document/office/visio': True,
    'document/office/word': True,
    'document/office/wordpro': True,
    'document/office/wordperfect': True,
    'document/email': True,
    'document/pdf': True,
    'document/unknown': True,
    'executable/unknown': True,
    'executable/mach-o': True,
    'executable/windows/com': True,
    'executable/windows/dos': True,
    'executable/windows/pe': True,
    'executable/windows/pe32': True,
    'executable/windows/pe64': True,
    'executable/windows/dll32': True,
    'executable/windows/dll64': True,
    'executable/linux/elf32': True,
    'executable/linux/elf64': True,
    'executable/linux/so32': True,
    'executable/linux/so64': True,
    'font/texture/pvr': True,
    'image/bmp': True,
    'image/gif': True,
    'image/jpg': True,
    'image/png': True,
    'image/svg': True,
    'image/texture/ka3d': True,
    'image/texture/ktx': True,
    'image/texture/pkm': True,
    'image/texture/powervr': True,
    'image/texture/rvio': True,
    'image/unknown': True,
    'ios/ipa': True,
    'java/class': True,
    'java/jar': True,
    'java/java': True,
    'java/jbdiff': True,
    'java/manifest': True,
    'java/signature': True,
    'java/unknown': True,
    'meta/torrent': True,
    'meta/shortcut/windows': True,
    'metadata/memorydump': True,
    'metadata/sysmon': True,
    'network/sff': True,
    'network/tcpdump': True,
    'network/unknown': True,
    'resource/big': True,
    'resource/ccz': True,
    'resource/cpk': True,
    'resource/dz': True,
    'resource/pak': True,
    'resource/ptc': True,
    'resource/sbm': True,
    'resource/sbr': True,
    'resource/sc': True,
    'resource/unity': True,
    'text/calendar': True,
    'text/json': True,
    'text/markdown': True,
    'quarantine/ahnlab': True,
    'quarantine/avast': True,
    'quarantine/avira': True,
    'quarantine/mcafee': True,
    'quarantine/windowsdefender': True,
    'unknown': True,
}

custom_rules = os.path.join(modulepath(__name__), 'custom.magic')
RULE_PATH = ':'.join((custom_rules, '/usr/share/file/magic.mgc'))
