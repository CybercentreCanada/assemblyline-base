import importlib
import sys


def load_module_by_path(name: str, lookup_path=None):
    if lookup_path and lookup_path not in sys.path:
        sys.path.append(lookup_path)

    module_path, _sep, module_attribute_name = name.rpartition('.')
    module = sys.modules.get(module_path, None)
    if not module:
        module = importlib.import_module(module_path)
    return getattr(module, module_attribute_name)
