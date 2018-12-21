"""
Defines an interface for hash searching.

Given a file hash, try to generate a quick description of the file.

This is extended and used by several services. To expose a service's
datasource specialization, it can be added to the 'datasources' seed key.

The assemblyline core comes with an implementation for searching all results `al.py`
or the alerts streams `alert.py`. The base class/interface is defined in `common.py`
"""
