from assemblyline.datastore.odm import Keyword, Text, List
from assemblyline.datastore.odm import Date, Integer, Float, Boolean

# Simple types can be resolved by a direct mapping
__type_mapping = {
    Keyword: 'keyword',
    Boolean: 'boolean',
    Integer: 'long',
    Float: 'float',
}

def build_mapping(field_data, prefix=None, mappings=None):
    """
    The mapping for Elasticsearch based on a python model object.
    """

    prefix = prefix or []
    mappings = mappings or {}

    def set_mapping(name, field, body):
        name = name.strip('.')
        mappings[name] = body
        if not field.index:
            mappings[name]['enabled'] = False
        if field.store:
            mappings[name]['store'] = True

    # Fill in the sections
    for field in field_data:
        path = prefix + ([field.name] if field.name else [])
        name = '.'.join(path)

        if isinstance(field, (Keyword, Boolean, Integer, Float)):
            set_mapping(name, field, {
                'type': __type_mapping[field.__class__]
            })

        elif isinstance(field, Text):
            set_mapping(name, field, {
                'type': 'text',
                'analyzer': 'text_general'
            })

        elif isinstance(field, Date):
            set_mapping(name, field, {
                'type': 'date',
                'format': 'date_optional_time||epoch_millis',
            })

        elif isinstance(field, List):
            build_mapping([field.child_type], prefix=path, mappings=mappings)

        else:
            raise NotImplementedError(f"Unknown type for elasticsearch schema: {field.__class__}")

    return mappings
    # @visits(Compound)
    # def compound(self, field, prefix=''):
    #     prefix = prefix + (field.name + '.') if field.name else ''
    #     for child in field.children.values():
    #         self.visit(child, prefix=prefix)
