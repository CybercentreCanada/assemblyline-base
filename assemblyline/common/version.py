"""
Try to find the version of the code base that is running or assume an arbitrary one for testing.
"""
import os
import re


ASSEMBLYLINE_VERSION = os.environ.get('ASSEMBLYLINE_VERSION', "4.0.0.dev0")

PATTERN = r'v?(?P<framework>[0-9]+)\.(?P<system>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<channel>dev|stable)?(?P<build>[0-9]+)'

matching = re.match(PATTERN, ASSEMBLYLINE_VERSION, re.IGNORECASE)
if matching:
    groups = matching.groupdict()
else:
    raise EnvironmentError("Could not process the ASSEMBLYLINE_VERSION variable to extract a release version.")

FRAMEWORK_VERSION = int(groups['framework'])
SYSTEM_VERSION = int(groups['system'])
BUILD_MINOR = int(groups['minor'])
