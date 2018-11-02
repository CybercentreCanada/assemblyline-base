"""

TODO copyto

"""
from assemblyline.datastore.odm import Keyword, Text, List, Compound
from assemblyline.datastore.odm import Date, Integer, Float, Boolean

# Simple types can be resolved by a direct mapping
__type_mapping = {
    Keyword: 'string',
    Boolean: 'boolean',
    Integer: 'pint',
    Float: 'pfloat',
    Date: 'pdate',
}

__multi_type_mapping = {
    Keyword: 'strings',
    Boolean: 'booleans',
    Integer: 'pints',
    Float: 'pfloats',
    Date: 'pdates',
}


def build_mapping(field_data, prefix=None, mappings=None, multivalued=False):
    """
    The mapping for solr based on a python model object.
    """

    types = __multi_type_mapping if multivalued else __type_mapping
    prefix = prefix or []
    mappings = mappings or []

    def set_mapping(name, field, type):
        name = name.strip('.')
        index = 'true' if field.index else 'false'
        store = 'true' if field.store else 'false'
        mappings.append(f'<field name="{name}" type="{type}" indexed="{index}" stored="{store}"/>')

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, (Keyword, Boolean, Integer, Float, Date)):
            set_mapping(name, field, types[field.__class__])

        elif isinstance(field, Text):
            set_mapping(name, field, 'text_general')

        elif isinstance(field, List):
            build_mapping([field.child_type], prefix=path, mappings=mappings, multivalued=True)

        elif isinstance(field, Compound):
            build_mapping(field.fields().values(), prefix=path, mappings=mappings, multivalued=multivalued)

        else:
            raise NotImplementedError(f"Unknown type for elasticsearch schema: {field.__class__}")

    return '\n'.join(mappings)
