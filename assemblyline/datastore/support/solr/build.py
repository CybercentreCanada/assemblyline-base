from assemblyline.odm import Keyword, Text, Date, Integer, Float, Boolean, Classification, Enum, List, Compound, Mapping

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

back_mapping = {v: k for k, v in __type_mapping.items() if k not in [Enum, Classification]}


def build_mapping(field_data, prefix=None, multivalued=False):
    """
    The mapping for riak based on a python model object.
    """

    prefix = prefix or []
    mappings = []

    def set_mapping(p_name, p_field, p_type):
        temp_mappings = []
        p_name = p_name.strip('.')
        index = 'true' if p_field.index else 'false'
        store = 'true' if p_field.store else 'false'
        multi = 'true' if multivalued else 'false'
        docvalues = 'docValues="false"' if not p_field.index else ''
        temp_mappings.append(f'<field name="{p_name}" type="{p_type}" indexed="{index}" '
                             f'stored="{store}" multiValued="{multi}" {docvalues}/>')

        for other_field in p_field.copyto:
            temp_mappings.append(f'<copyField source="{p_name}" dest="{other_field}"/>')

        return temp_mappings

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, (Boolean, Integer, Float, Date)):
            # noinspection PyTypeChecker
            mappings.extend(set_mapping(name, field, __type_mapping[field.__class__]))

        elif isinstance(field, (Keyword, Text)):
            # noinspection PyTypeChecker
            mappings.extend(set_mapping(name, field, __type_mapping[field.__class__]))

        elif isinstance(field, List):
            mappings.extend(build_mapping([field.child_type], prefix=path, multivalued=True))

        elif isinstance(field, Compound):
            mappings.extend(build_mapping(field.fields().values(), prefix=path, multivalued=multivalued))

        elif isinstance(field, Mapping):
            # TODO: Does not work for Mappings of List or Mapping
            child = field.child_type
            if isinstance(child, List):
                path.append("*")
                mappings.extend(build_mapping(child, prefix=path, multivalued=True))
            elif isinstance(child, Mapping):
                path.append("*")
                mappings.extend(build_mapping(child.fields().values(), prefix=path, multivalued=multivalued))
            else:
                index = 'true' if child.index else 'false'
                store = 'true' if child.store else 'false'
                solr_type = __type_mapping[child.__class__]
                if ".*" not in name:
                    name = f"{name}.*"
                mappings.append(f'<dynamicField name="{name}" type="{solr_type}" indexed="{index}" stored="{store}" />')
                for other_field in field.copyto + child.copyto:
                    mappings.append(f'<copyField source="{name}" dest="{other_field}"/>')

        else:
            raise NotImplementedError(f"Unknown type for solr schema: {field.__class__}")

    return mappings
