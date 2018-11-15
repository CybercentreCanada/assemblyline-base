from assemblyline.datastore.odm import Keyword, Text, List, Compound, Date, Integer, Float, Boolean, Mapping

# Simple types can be resolved by a direct mapping
__type_mapping = {
    Keyword: 'keyword',
    Boolean: 'boolean',
    Integer: 'integer',
    Float: 'float',
    Date: 'date',
    Text: 'text'
}
back_mapping = {v: k for k, v in __type_mapping.items()}


def build_mapping(field_data, prefix=None, mappings=None, dynamic=None):
    """
    The mapping for Elasticsearch based on a python model object.
    """

    prefix = prefix or []
    mappings = mappings or {}
    dynamic = dynamic or []

    def set_mapping(name, field, body):
        name = name.strip('.')
        mappings[name] = body
        if not field.index:
            mappings[name]['enabled'] = False
        if field.store:
            mappings[name]['store'] = True
        if field.copyto:
            assert len(field.copyto) == 1
            mappings[name]['copy_to'] = field.copyto[0]

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, (Keyword, Boolean, Integer, Float, Text)):
            set_mapping(name, field, {
                'type': __type_mapping[field.__class__]
            })

        elif isinstance(field, Date):
            set_mapping(name, field, {
                'type': __type_mapping[field.__class__],
                'format': 'date_optional_time||epoch_millis',
            })

        elif isinstance(field, List):
            build_mapping([field.child_type], prefix=path, mappings=mappings, dynamic=dynamic)

        elif isinstance(field, Compound):
            build_mapping(field.fields().values(), prefix=path, mappings=mappings, dynamic=dynamic)

        elif isinstance(field, Mapping):
            build_templates(name, field.child_type, dynamic)

        else:
            raise NotImplementedError(f"Unknown type for elasticsearch schema: {field.__class__}")

    # The final template must match everything and disable indexing
    # this effectively disables dynamic indexing EXCEPT for the templates
    # we have defined
    dynamic.append({'refuse_all_implicit_mappings': {
        "match_mapping_type": "*",
        "match": "*",
        "mapping": {
            "enabled": False
        }
    }})

    return mappings, dynamic


def build_templates(name, field, dynamic):
    if isinstance(field, (Keyword, Boolean, Integer, Float, Text)):
        template = {
            "match_mapping_type": "*",
            "path_match": f"{name}.*",
            "mapping": {
                "type": __type_mapping[field.__class__],
                "enabled": True,
            }
        }

        if not field.index:
            template['mapping']['enabled'] = False
        if field.store:
            template['mapping']['store'] = True
        if field.copyto:
            assert len(field.copyto) == 1
            template['mapping']['copy_to'] = field.copyto[0]

        dynamic.append({f"{name}_tpl": template})

    else:
        raise NotImplementedError(f"Unknown type for elasticsearch dynamic mapping: {field.__class__}")
