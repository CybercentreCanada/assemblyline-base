from assemblyline.odm import Keyword, Text, List, Compound, Date, Integer, \
    Float, Boolean, Mapping, Classification, Enum, Any, UUID

# Simple types can be resolved by a direct mapping
__type_mapping = {
    Keyword: 'keyword',
    Boolean: 'boolean',
    Integer: 'integer',
    Float: 'float',
    Date: 'date',
    Text: 'text',
    Classification: 'keyword',
    Enum: 'keyword',
    UUID: 'keyword'
}
# TODO: We might want to use custom analyzers for Classification and Enum and not create special backmapping cases
back_mapping = {v: k for k, v in __type_mapping.items() if k not in [Enum, Classification, UUID]}


def build_mapping(field_data, prefix=None, allow_refuse_implicit=True):
    """
    The mapping for Elasticsearch based on a python model object.
    """

    prefix = prefix or []
    mappings = {}
    dynamic = []

    def set_mapping(temp_field, body):
        body['index'] = temp_field.index
        body['store'] = temp_field.store
        if temp_field.copyto:
            assert len(temp_field.copyto) == 1
            body['copy_to'] = temp_field.copyto[0]

        return body

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, (Keyword, Boolean, Integer, Float, Text)):
            mappings[name.strip(".")] = set_mapping(field, {
                'type': __type_mapping[field.__class__]
            })

        elif isinstance(field, Date):
            mappings[name.strip(".")] = set_mapping(field, {
                'type': __type_mapping[field.__class__],
                'format': 'date_optional_time||epoch_millis',
            })

        elif isinstance(field, List):
            temp_mappings, temp_dynamic = build_mapping([field.child_type], prefix=path,
                                                        allow_refuse_implicit=False)
            mappings.update(temp_mappings)
            dynamic.extend(temp_dynamic)

        elif isinstance(field, Compound):
            temp_mappings, temp_dynamic = build_mapping(field.fields().values(), prefix=path,
                                                        allow_refuse_implicit=False)
            mappings.update(temp_mappings)
            dynamic.extend(temp_dynamic)

        elif isinstance(field, Mapping):
            if not isinstance(field.child_type, Any):
                dynamic.extend(build_templates(f'{name}.*', field.child_type))

        elif isinstance(field, Any):
            continue
        else:
            raise NotImplementedError(f"Unknown type for elasticsearch schema: {field.__class__}")

    # The final template must match everything and disable indexing
    # this effectively disables dynamic indexing EXCEPT for the templates
    # we have defined
    if not dynamic and allow_refuse_implicit:
        # We cannot use the dynamic type matching if others are in play because they conflict with each other
        # TODO: Find a way to make them work together.
        dynamic.append({'refuse_all_implicit_mappings': {
            "match_mapping_type": "*",
            "match": "*",
            "mapping": {
                "enabled": False
            }
        }})

    return mappings, dynamic


def build_templates(name, field, nested_template=False) -> list:
    if isinstance(field, (Keyword, Boolean, Integer, Float, Text)):
        if nested_template:
            main_template = {
                "match": f"{name}",
                "mapping": {
                    "type": "nested",
                    "index": field.index,
                    "store": field.store
                }
            }
            if field.copyto:
                assert len(field.copyto) == 1
                main_template['mapping']['copy_to'] = field.copyto[0]

            return [{f"nested_{name}": main_template}]
        else:
            field_template = {
                "path_match": name,
                "mapping": {
                    "type": __type_mapping[field.__class__],
                }
            }

            field_template['mapping']['index'] = field.index
            field_template['mapping']['store'] = field.store
            if field.copyto:
                assert len(field.copyto) == 1
                field_template['mapping']['copy_to'] = field.copyto[0]

            return [{f"{name}_tpl": field_template}]

    elif isinstance(field, (Mapping, List)):
        temp_name = name
        if field.name:
            temp_name = f"{name}.{field.name}"
        return build_templates(temp_name, field.child_type, nested_template=True)

    elif isinstance(field, Compound):
        temp_name = name
        if field.name:
            temp_name = f"{name}.{field.name}"

        out = []
        for sub_name, sub_field in field.fields().items():
            sub_name = f"{temp_name}.{sub_name}"
            out.extend(build_templates(sub_name, sub_field))

        return out

    else:
        raise NotImplementedError(f"Unknown type for elasticsearch dynamic mapping: {field.__class__}")
