from assemblyline import odm
from assemblyline.datastore.collection import ESCollection
from assemblyline.datastore.support.build import build_mapping


@odm.model(index=True)
class OdmTestMapping1(odm.Model):
    stable_text_field = odm.keyword()
    swapped_text_field = odm.keyword()
    stable_number_field = odm.integer()
    swapped_number_field = odm.integer()


@odm.model(index=True)
class OdmTestMapping2(odm.Model):
    stable_text_field = odm.keyword()
    swapped_text_field = odm.wildcard()
    stable_number_field = odm.integer()
    swapped_number_field = odm.long()


def test_example_mapping_type():
    """Test that the example models produce the expected mapping types"""
    properties, dynamic = build_mapping(OdmTestMapping1.fields().values())

    # There should be no dynamic mappings, just one rule forbidding implicit mappings
    assert len(dynamic) == 1
    assert 'refuse_all_implicit_mappings' in dynamic[0]

    # Check that the static fields have the mapping type we want
    assert len(properties) == 4
    assert properties['stable_text_field']['type'] == 'keyword'
    assert properties['swapped_text_field']['type'] == 'keyword'
    assert properties['stable_number_field']['type'] == 'integer'
    assert properties['swapped_number_field']['type'] == 'integer'

    properties, dynamic = build_mapping(OdmTestMapping2.fields().values())

    # There should be no dynamic mappings, just one rule forbidding implicit mappings
    assert len(dynamic) == 1
    assert 'refuse_all_implicit_mappings' in dynamic[0]

    # Check that the static fields have the mapping type we want
    assert len(properties) == 4
    assert properties['stable_text_field']['type'] == 'keyword'
    assert properties['swapped_text_field']['type'] == 'wildcard'
    assert properties['stable_number_field']['type'] == 'integer'
    assert properties['swapped_number_field']['type'] == 'long'


def test_field_upgrade_ok(datastore_connection):
    """Test that changing a field from keyword to wildcard doesn't break anything."""
    # Clean up from any previous runs
    collection = ESCollection(datastore_connection.ds, "testmapping", OdmTestMapping1, validate=False)
    collection.wipe(recreate=False)

    # Create the collection in elastic 
    collection = ESCollection(datastore_connection.ds, "testmapping", OdmTestMapping1, validate=True)
    properties = collection.fields()
    assert properties['stable_text_field']['type'] == 'keyword'
    assert properties['swapped_text_field']['type'] == 'keyword'
    assert properties['stable_number_field']['type'] == 'integer'
    assert properties['swapped_number_field']['type'] == 'integer'

    # Open that same collection using the new mapping
    collection = ESCollection(datastore_connection.ds, "testmapping", OdmTestMapping2, validate=True)

    # Check that the fields haven't changed
    properties = collection.fields()
    assert properties['stable_text_field']['type'] == 'keyword'
    assert properties['swapped_text_field']['type'] == 'keyword'
    assert properties['stable_number_field']['type'] == 'integer'
    assert properties['swapped_number_field']['type'] == 'integer'

    # Reindex
    collection.reindex()

    # Check that the fields match the new model
    properties = collection.fields()
    assert properties['stable_text_field']['type'] == 'keyword'
    assert properties['swapped_text_field']['type'] == 'wildcard'
    assert properties['stable_number_field']['type'] == 'integer'
    assert properties['swapped_number_field']['type'] == 'long'
