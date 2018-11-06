"""

TODO copyto

"""
from assemblyline.datastore.odm import Keyword, Text, List, Compound
from assemblyline.datastore.odm import Date, Integer, Float, Boolean

# Simple types can be resolved by a direct mapping
type_mapping = {
    Text: 'string',
    Keyword: 'string',
    Boolean: 'boolean',
    Integer: 'int',
    Float: 'float',
    Date: 'date',
}


def build_mapping(field_data, prefix=None, mappings=None, multivalued=False):
    """
    The mapping for riak based on a python model object.
    """

    prefix = prefix or []
    mappings = mappings or []

    def set_mapping(name, field, type, fields=''):
        name = name.strip('.')
        mappings.append(f'<field name="{name}" type="{type}" indexed="{field.index}" stored="{field.store}" multiValued="{multivalued}" {fields} />')

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, (Boolean, Integer, Float, Date)):
            set_mapping(name, field, type_mapping[field.__class__])

        elif isinstance(field, (Keyword, Text)):
            set_mapping(name, field, type_mapping[field.__class__], 'required="true" default=""')

        elif isinstance(field, List):
            build_mapping([field.child_type], prefix=path, mappings=mappings, multivalued=True)

        elif isinstance(field, Compound):
            build_mapping(field.fields().values(), prefix=path, mappings=mappings, multivalued=multivalued)

        else:
            raise NotImplementedError(f"Unknown type for elasticsearch schema: {field.__class__}")

    return '\n'.join(mappings)
