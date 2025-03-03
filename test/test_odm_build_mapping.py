from assemblyline import odm
from assemblyline.datastore.support.build import build_mapping


def test_simple_fields():
    @odm.model()
    class Inner(odm.Model):
        text = odm.Text()
        key = odm.keyword()
        index_key = odm.keyword(index=True)
        no_index_key = odm.keyword(index=False)

    @odm.model(index=True)
    class NestAlwaysIndex(odm.Model):
        a = odm.compound(Inner)
        b = odm.compound(Inner, index=True)
        c = odm.compound(Inner, index=False)

    @odm.model()
    class Outer(odm.Model):
        a = odm.compound(Inner)
        b = odm.compound(Inner, index=True)
        c = odm.compound(Inner, index=False)
        d = odm.compound(NestAlwaysIndex)
        e = odm.compound(NestAlwaysIndex, index=False)

    # Build the mappings
    static, dynamic = build_mapping(Outer.fields().values())

    # Check the static fields
    FIELDS = {
        'a.': [
            ("text", "text", None),
            ("key", "keyword", None),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
        'b.': [
            ("text", "text", True),
            ("key", "keyword", True),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
        'c.': [
            ("text", "text", False),
            ("key", "keyword", False),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
        'd.a.': [
            ("text", "text", True),
            ("key", "keyword", True),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
        'd.b.': [
            ("text", "text", True),
            ("key", "keyword", True),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
        'd.c.': [
            ("text", "text", False),
            ("key", "keyword", False),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
        'e.a.': [
            ("text", "text", True),
            ("key", "keyword", True),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
        'e.b.': [
            ("text", "text", True),
            ("key", "keyword", True),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
        'e.c.': [
            ("text", "text", False),
            ("key", "keyword", False),
            ("index_key", "keyword", True),
            ("no_index_key", "keyword", False),
        ],
    }

    for prefix, fields in FIELDS.items():
        for name, type_, indexed in fields:
            field = static.pop(prefix + name)
            assert field['type'] == type_
            assert field['index'] is indexed, prefix + name
    assert len(static) == 0

    # Make sure there are no dynamic fields
    assert len(dynamic) == 1
    assert list(dynamic[0].keys()) == ['refuse_all_implicit_mappings']


def test_dynamic_fields():
    @odm.model()
    class Inner(odm.Model):
        text = odm.Text()
        key = odm.keyword()
        index_key = odm.keyword(index=True)
        no_index_key = odm.keyword(index=False)

    @odm.model(index=True)
    class NestAlwaysIndex(odm.Model):
        a = odm.compound(Inner)
        b = odm.compound(Inner, index=True)
        c = odm.compound(Inner, index=False)

    # Only mappings where the mapping itself is marked for indexing will have its subfields indexed
    @odm.model(index=True)
    class Outer(odm.Model):
        a = odm.mapping(odm.compound(Inner), index=False)
        b = odm.mapping(odm.compound(Inner, index=True))
        c = odm.mapping(odm.compound(Inner, index=False))
        d = odm.mapping(odm.compound(NestAlwaysIndex), index=False)
        e = odm.mapping(odm.compound(NestAlwaysIndex, index=False))
        f = odm.mapping(odm.integer())

    # Build the mappings
    static, dynamic = build_mapping(Outer.fields().values())

    # make sure the static lines corresponding to mappings are disabled
    for name in ['a', 'c', 'd', 'e']:
        field = static.pop(name)
        assert field['enabled'] is False
        assert field['type'] == 'object'
    assert len(static) == 0, static

    # Make sure there are dynamic rules for the expected fields
    rules = {}
    for row in dynamic:
        for key, config in row.items():
            assert key not in rules
            rules[key] = config
    assert rules == {
        'b.*.text_tpl': {'mapping': {'index': True, 'type': 'text'}, 'path_match': 'b.*.text'},
        'b.*.key_tpl': {'mapping': {'index': True, 'type': 'keyword'}, 'path_match': 'b.*.key'},
        'b.*.index_key_tpl': {'mapping': {'index': True, 'type': 'keyword'}, 'path_match': 'b.*.index_key'},
        'b.*.no_index_key_tpl': {'mapping': {'index': False, 'type': 'keyword'}, 'path_match': 'b.*.no_index_key'},
        'f.*_tpl': {'mapping': {'index': True, 'type': 'integer'}, 'path_match': 'f.*'},
    }


def test_dynamic_fields_simple():
    """Simplified version of the above test for checking some more common cases"""
    @odm.model()
    class InnerNone(odm.Model):
        a = odm.keyword()
        b = odm.keyword(index=True)

    @odm.model(index=True)
    class InnerTrue(odm.Model):
        a = odm.keyword()
        b = odm.keyword(index=True)

    @odm.model()
    class Outer(odm.Model):
        a = odm.mapping(odm.compound(InnerNone), index=True)
        b = odm.mapping(odm.compound(InnerNone, index=True))
        c = odm.mapping(odm.compound(InnerNone))
        d = odm.mapping(odm.compound(InnerTrue))
        
    # Build the mappings
    static, dynamic = build_mapping(Outer.fields().values())

    # There shouldn't be any static mappings
    assert len(static) == 0

    # Make sure there are dynamic rules for the expected fields
    rules = {}
    for row in dynamic:
        for key, config in row.items():
            assert key not in rules
            rules[key] = config
    assert rules == {
        'a.*.a_tpl': {'mapping': {'type': 'keyword', 'index': True}, 'path_match': 'a.*.a'},
        'a.*.b_tpl': {'mapping': {'type': 'keyword', 'index': True}, 'path_match': 'a.*.b'},
        'b.*.a_tpl': {'mapping': {'type': 'keyword', 'index': True}, 'path_match': 'b.*.a'},
        'b.*.b_tpl': {'mapping': {'type': 'keyword', 'index': True}, 'path_match': 'b.*.b'},
        # All the same exept this one
        'c.*.a_tpl': {'mapping': {'type': 'keyword', 'index': None}, 'path_match': 'c.*.a'},
        'c.*.b_tpl': {'mapping': {'type': 'keyword', 'index': True}, 'path_match': 'c.*.b'},
        'd.*.a_tpl': {'mapping': {'type': 'keyword', 'index': True}, 'path_match': 'd.*.a'},
        'd.*.b_tpl': {'mapping': {'type': 'keyword', 'index': True}, 'path_match': 'd.*.b'},
    }
