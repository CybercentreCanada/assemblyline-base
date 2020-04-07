import logging
import requests
import re

#REF:https://stackoverflow.com/questions/48380452/mask-out-sensitive-information-in-python-log
class SensitiveFormatter(logging.Formatter):
    """Formatter that removes sensitive information in urls."""
    @staticmethod
    def _filter(s):
        return re.sub(r':\/\/(.*?)\@', r'://', s)

    def format(self, record):
        original = logging.Formatter.format(self, record)
        return self._filter(original)

LOG_FORMAT = '%(asctime)s [%(threadName)-16s] %(filename)27s:%(lineno)-4d %(levelname)7s| %(message)s'
log = logging.getLogger(__name__)

for handler in logging.root.handlers:
   handler.setFormatter(SensitiveFormatter(LOG_FORMAT))

log.warning('https://not:shown@httpbin.org/basic-auth/expected-user/expected-pass')


def sanitize(link):
    #Expected:  "..blah blah <protocol>://<s_user>:<s_pass>@<server> blah blah.."
    #Result:    "..blah blah <protocol>://<server> blah blah.."
    if "://" in link and "@"  in link:
        protocol,server = link.split('://')[0],link.split('@')[1]
        link = protocol + "://" + server
    return link

testMsg = "Problem connecting to http://user:pass@server! CRISIS!"
l = logging.Logger("logger")
l.warning(testMsg)
l.warning(sanitize(testMsg))