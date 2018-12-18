from assemblyline.odm import Keyword, Text, List, Compound, Date, Integer, \
    Float, Boolean, Mapping, Classification, Enum
from assemblyline.datastore.support.riak.build import back_mapping as riak_back_mapping

# Simple types can be resolved by a direct mapping
__type_mapping = {
    Text: 'text',
    Keyword: 'string',
    Boolean: 'boolean',
    Integer: 'pint',
    Float: 'pfloat',
    Date: 'pdate',
    Classification: 'string',
    Enum: 'string'
}

back_mapping = riak_back_mapping
back_mapping.update({v: k for k, v in __type_mapping.items() if k not in [Enum, Classification]})


def build_mapping(field_data, prefix=None, mappings=None, multivalued=False):
    """
    The mapping for solr based on a python model object.
    """

    prefix = prefix or []
    mappings = mappings or []

    def set_mapping(p_name, p_field, p_type):
        p_name = p_name.strip('.')
        index = 'true' if p_field.index else 'false'
        store = 'true' if p_field.store else 'false'
        multi = 'true' if multivalued else 'false'
        mappings.append(f'<field name="{p_name}" type="{p_type}" indexed="{index}" stored="{store}" '
                        f'multiValued="{multi}"/>')
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
            set_mapping(name, field, __type_mapping[field.__class__])

        elif isinstance(field, List):
            build_mapping([field.child_type], prefix=path, mappings=mappings, multivalued=True)

        elif isinstance(field, Compound):
            build_mapping(field.fields().values(), prefix=path, mappings=mappings, multivalued=multivalued)

        elif isinstance(field, Mapping):
            # TODO: Does not work for Mappings of List or Mapping
            child = field.child_type
            index = 'true' if child else 'false'
            store = 'true' if child else 'false'
            solr_type = __type_mapping[child.__class__]
            mappings.append(f'<dynamicField name="{name}.*" type="{solr_type}" indexed="{index}" stored="{store}" />')
            for other_field in field.copyto + child.copyto:
                mappings.append(f'<copyField source="{name}.*" dest="{other_field}"/>')

        else:
            raise NotImplementedError(f"Unknown type for elasticsearch schema: {field.__class__}")

    return '\n'.join(mappings)
