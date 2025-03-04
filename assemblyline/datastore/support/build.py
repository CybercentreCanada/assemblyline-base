from assemblyline.odm.base import _Field
from assemblyline.odm import Keyword, Wildcard, Text, List, Compound, Date, Integer, Long, \
    Float, Boolean, Mapping, Classification, Enum, Any, UUID, Optional, IP, Domain, URI, URIPath, MAC, PhoneNumber, \
    SSDeepHash, SHA1, SHA256, MD5, Platform, Processor, ClassificationString, FlattenedObject, Email, UpperKeyword, \
    Json, ValidatedKeyword, UNCPath

# Simple types can be resolved by a direct mapping
__type_mapping = {
    Keyword: 'keyword',
    Wildcard: 'wildcard',
    Boolean: 'boolean',
    Integer: 'integer',
    Long: 'long',
    Float: 'float',
    Date: 'date',
    Text: 'text',
    Classification: 'keyword',
    ClassificationString: 'keyword',
    Enum: 'keyword',
    UUID: 'keyword',
    IP: 'ip',
    Domain: 'keyword',
    Email: 'keyword',
    URI: 'keyword',
    UNCPath: 'keyword',
    URIPath: 'keyword',
    MAC: 'keyword',
    PhoneNumber: 'keyword',
    SSDeepHash: 'text',
    SHA1: 'keyword',
    SHA256: 'keyword',
    MD5: 'keyword',
    Platform: 'keyword',
    Processor: 'keyword',
    FlattenedObject: 'nested',
    Any: 'keyword',
    UpperKeyword: 'keyword',
    Json: 'keyword',
    ValidatedKeyword: 'keyword'
}
__analyzer_mapping = {
    SSDeepHash: 'text_fuzzy',
}
__normalizer_mapping = {
    SHA1: 'lowercase_normalizer',
    SHA256: 'lowercase_normalizer',
    MD5: 'lowercase_normalizer',
}
# TODO: We might want to use custom analyzers for Classification and Enum and not create special backmapping cases
back_mapping = {v: k for k, v in __type_mapping.items() if k not in [Enum, Classification, UUID, IP, Domain, URI,
                                                                     URIPath, MAC, PhoneNumber, SSDeepHash, Email,
                                                                     SHA1, SHA256, MD5, Platform, Processor,
                                                                     ClassificationString, Any, UpperKeyword, Json,
                                                                     ValidatedKeyword, UNCPath]}
back_mapping.update({x: Keyword for x in set(__analyzer_mapping.values())})


def build_mapping(field_data, prefix=None, allow_refuse_implicit=True):
    """
    The mapping for Elasticsearch based on a python model object.
    """

    prefix = prefix or []
    mappings = {}
    dynamic = []

    def set_mapping(temp_field: _Field, body):
        body['index'] = temp_field.index
        if temp_field.store is not None:
            body['store'] = temp_field.store
        if body.get('type', 'text') != 'text':
            body['doc_values'] = temp_field.index
        if temp_field.copyto:
            assert len(temp_field.copyto) == 1
            body['copy_to'] = temp_field.copyto[0]

        return body

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, Classification):
            mappings[name.strip(".")] = set_mapping(field, {
                'type': __type_mapping[field.__class__]
            })
            if "." not in name:
                mappings.update({
                    "__access_lvl__": {
                        'type': 'integer',
                        'index': True},
                    "__access_req__": {
                        'type': 'keyword',
                        'index': True},
                    "__access_grp1__": {
                        'type': 'keyword',
                        'index': True},
                    "__access_grp2__": {
                        'type': 'keyword',
                        'index': True},
                })

        elif isinstance(field, (Boolean, Integer, Long, Float, Text)):
            mappings[name.strip(".")] = set_mapping(field, {
                'type': __type_mapping[field.__class__]
            })

        elif field.__class__ in __analyzer_mapping:
            mappings[name.strip(".")] = set_mapping(field, {
                'type': __type_mapping[field.__class__],
                "analyzer": __analyzer_mapping[field.__class__]
            })

        elif isinstance(field, Wildcard):
            es_data_type = __type_mapping[field.__class__]
            data = {'type': es_data_type}
            mappings[name.strip(".")] = data

        elif isinstance(field, Keyword):
            es_data_type = __type_mapping[field.__class__]
            data = {'type': es_data_type}
            if es_data_type == "keyword":
                data["ignore_above"] = 8191  # The maximum always safe value in elasticsearch
            if field.__class__ in __normalizer_mapping:
                data['normalizer'] = __normalizer_mapping[field.__class__]
            mappings[name.strip(".")] = set_mapping(field, data)

        elif isinstance(field, Date):
            mappings[name.strip(".")] = set_mapping(field, {
                'type': __type_mapping[field.__class__],
                'format': 'date_optional_time||epoch_millis',
            })

        elif isinstance(field, FlattenedObject):
            if not field.index or isinstance(field.child_type, Any):
                mappings[name.strip(".")] = {"type": "object", "enabled": False}
            else:
                dynamic.extend(build_templates(f'{name}.*', field.child_type, nested_template=True, index=field.index))

        elif isinstance(field, List):
            temp_mappings, temp_dynamic = build_mapping([field.child_type], prefix=path,
                                                        allow_refuse_implicit=False)
            mappings.update(temp_mappings)
            dynamic.extend(temp_dynamic)

        elif isinstance(field, Optional):
            temp_mappings, temp_dynamic = build_mapping([field.child_type], prefix=prefix,
                                                        allow_refuse_implicit=False)
            mappings.update(temp_mappings)
            dynamic.extend(temp_dynamic)

        elif isinstance(field, Compound):
            temp_mappings, temp_dynamic = build_mapping(field.fields().values(), prefix=path,
                                                        allow_refuse_implicit=False)
            mappings.update(temp_mappings)
            dynamic.extend(temp_dynamic)

        elif isinstance(field, Mapping):
            if not field.index or isinstance(field.child_type, Any):
                mappings[name.strip(".")] = {"type": "object", "enabled": False}
            else:
                dynamic.extend(build_templates(f'{name}.*', field.child_type, index=field.index))

        elif isinstance(field, Any):
            if field.index:
                raise ValueError(f"Any may not be indexed: {name}")

            mappings[name.strip(".")] = {
                "type": "keyword",
                "index": False,
                "doc_values": False
            }

        else:
            raise NotImplementedError(f"Unknown type for elasticsearch schema: {field.__class__}")

    # The final template must match everything and disable indexing
    # this effectively disables dynamic indexing EXCEPT for the templates
    # we have defined
    if not dynamic and allow_refuse_implicit:
        # We cannot use the dynamic type matching if others are in play because they conflict with each other
        # TODO: Find a way to make them work together.
        dynamic.append({'refuse_all_implicit_mappings': {
            "match": "*",
            "mapping": {
                "index": False,
                "ignore_malformed": True,
            }
        }})

    return mappings, dynamic


def build_templates(name, field, nested_template=False, index=True) -> list:
    if isinstance(field, (Keyword, Boolean, Integer, Float, Text, Json)):
        if nested_template:
            main_template = {
                "match": f"{name}",
                "mapping": {
                    "type": "nested"
                }
            }

            return [{f"nested_{name}": main_template}]
        else:
            field_template = {
                "path_match": name,
                "mapping": {
                    "type": __type_mapping[field.__class__],
                }
            }

            field_template['mapping']['index'] = field.index
            if field.copyto:
                assert len(field.copyto) == 1
                field_template['mapping']['copy_to'] = field.copyto[0]

            return [{f"{name}_tpl": field_template}]

    elif isinstance(field, Any) or not index:
        field_template = {
            "path_match": name,
            "mapping": {
                "type": "keyword",
                "index": False
            }
        }

        if field.index:
            raise ValueError(f"Mapping to Any may not be indexed: {name}")
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

    elif isinstance(field, Optional):
        return build_templates(name, field.child_type, nested_template=nested_template)

    else:
        raise NotImplementedError(f"Unknown type for elasticsearch dynamic mapping: {field.__class__}")
