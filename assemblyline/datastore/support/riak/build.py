"""

TODO copyto

"""
from assemblyline.datastore.odm import Keyword, Text, List, Compound, Date, Integer, Float, Boolean

# Simple types can be resolved by a direct mapping
__type_mapping = {
    Text: 'text',
    Keyword: 'string',
    Boolean: 'boolean',
    Integer: 'int',
    Float: 'float',
    Date: 'date',
}

back_mapping = {v: k for k, v in __type_mapping.items()}


def build_mapping(field_data, prefix=None, mappings=None, multivalued=False):
    """
    The mapping for riak based on a python model object.
    """

    prefix = prefix or []
    mappings = mappings or []

    def set_mapping(p_name, p_field, p_type, fields=''):
        p_name = p_name.strip('.')
        index = 'true' if p_field.index else 'false'
        store = 'true' if p_field.store else 'false'
        multi = 'true' if multivalued else 'false'
        mappings.append(f'<field name="{p_name}" type="{p_type}" indexed="{index}" '
                        f'stored="{store}" multiValued="{multi}" {fields} />')
        for other_field in p_field.copyto:
            mappings.append(f'<copyField source="{p_name}" dest="{other_field}"/>')

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, (Boolean, Integer, Float, Date)):
            # noinspection PyTypeChecker
            set_mapping(name, field, __type_mapping[field.__class__])

        elif isinstance(field, (Keyword, Text)):
            # noinspection PyTypeChecker
            set_mapping(name, field, __type_mapping[field.__class__], 'required="true" default=""')

        elif isinstance(field, List):
            build_mapping([field.child_type], prefix=path, mappings=mappings, multivalued=True)

        elif isinstance(field, Compound):
            build_mapping(field.fields().values(), prefix=path, mappings=mappings, multivalued=multivalued)

        else:
            raise NotImplementedError(f"Unknown type for elasticsearch schema: {field.__class__}")

    return '\n'.join(mappings)
