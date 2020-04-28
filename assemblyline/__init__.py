import os

__version__ = "4.0.0.dev0"
_package_version_path = os.path.join(os.path.dirname(__file__), 'VERSION')
if os.path.exists(_package_version_path):
    with open(_package_version_path) as _package_version_file:
        __version__ = _package_version_file.read().strip()
