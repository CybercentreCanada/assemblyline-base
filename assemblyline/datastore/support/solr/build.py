from assemblyline.odm import Keyword, Text, Date, Integer, Float, Boolean, Classification, Enum, List, Compound, \
    Mapping, Any, UUID, Optional, IP, Domain, URI, URIPath, MAC, PhoneNumber, SSDeepHash, SHA1, SHA256, MD5

# Simple types can be resolved by a direct mapping
__type_mapping = {
    Text: 'text',
    Keyword: 'string',
    Boolean: 'boolean',
    Integer: 'pint',
    Float: 'pfloat',
    Date: 'pdate',
    Classification: 'string',
    Enum: 'string',
    UUID: 'string',
    IP: 'string',
    Domain: 'string',
    URI: 'string',
    URIPath: 'string',
    MAC: 'string',
    PhoneNumber: 'string',
    SSDeepHash: 'string',
    SHA1: 'string',
    SHA256: 'string',
    MD5: 'string'
}

back_mapping = {v: k for k, v in __type_mapping.items() if k not in [Enum, Classification, UUID, IP, Domain, URI,
                                                                     URIPath, MAC, PhoneNumber, SSDeepHash,
                                                                     SHA1, SHA256, MD5]}


def build_mapping(field_data, prefix=None, multivalued=False, dynamic=False):
    """
    The mapping for solr based on a python model object.
    """

    prefix = prefix or []
    mappings = []

    def set_mapping(p_name, p_field, p_type, dynamic):
        temp_mappings = []

        p_name = p_name.strip('.')
        if "*" in p_name and not p_name.endswith("*"):
            p_name = f"*{p_name.split('*')[-1]}"

        index = 'true' if p_field.index else 'false'
        store = 'true' if p_field.store else 'false'
        multi = 'true' if multivalued else 'false'
        docvalues = 'docValues="false"' if not p_field.index else ''
        temp_mappings.append(f'<{"dynamicField" if dynamic else "field"} name="{p_name}" type="{p_type}" '
                             f'indexed="{index}" stored="{store}" multiValued="{multi}" {docvalues}/>')

        for other_field in p_field.copyto:
            temp_mappings.append(f'<copyField source="{p_name}" dest="{other_field}"/>')

        return temp_mappings

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, Classification):
            mappings.extend(set_mapping(name, field, __type_mapping[field.__class__], dynamic))
            if "." not in name:
                mappings.extend([
                    '<field name="__access_lvl__" type="pint" indexed="true" stored="false" multiValued="false"/>',
                    '<field name="__access_req__" type="string" indexed="true" stored="false" multiValued="true"/>',
                    '<field name="__access_grp1__" type="string" indexed="true" stored="false" multiValued="true"/>',
                    '<field name="__access_grp2__" type="string" indexed="true" stored="false" multiValued="true"/>'
                ])

        elif isinstance(field, (Boolean, Integer, Float, Date)):
            # noinspection PyTypeChecker
            mappings.extend(set_mapping(name, field, __type_mapping[field.__class__], dynamic))

        elif isinstance(field, (Keyword, Text)):
            # noinspection PyTypeChecker
            mappings.extend(set_mapping(name, field, __type_mapping[field.__class__], dynamic))

        elif isinstance(field, List):
            mappings.extend(build_mapping([field.child_type], prefix=path, multivalued=True))

        elif isinstance(field, Optional):
            mappings.extend(build_mapping([field.child_type], prefix=prefix, multivalued=multivalued))

        elif isinstance(field, Compound):
            mappings.extend(build_mapping(field.fields().values(), prefix=path, multivalued=multivalued))

        elif isinstance(field, Mapping):
            # TODO: Does not work for Mappings of List or Mapping
            child = field.child_type
            if isinstance(child, List):
                path.append("*")
                mappings.extend(build_mapping(child, prefix=path, multivalued=True, dynamic=True))
            elif isinstance(child, Optional):
                path.append("*")
                mappings.extend(build_mapping(child, prefix=prefix, multivalued=multivalued, dynamic=True))
            elif isinstance(child, Mapping):
                path.append("*")
                mappings.extend(build_mapping(child.fields().values(), prefix=path,
                                              multivalued=multivalued, dynamic=True))
            elif isinstance(child, Compound):
                path.append("*")
                mappings.extend(build_mapping(child.fields().values(), prefix=path,
                                              multivalued=multivalued, dynamic=True))
            elif isinstance(child, Any):
                continue
            else:
                if ".*" not in name:
                    name = f"{name}.*"
                mappings.extend(set_mapping(name, child, __type_mapping[child.__class__], True))

        elif isinstance(field, Any):
            continue

        else:
            raise NotImplementedError(f"Unknown type for solr schema: {field.__class__}")

    return mappings
