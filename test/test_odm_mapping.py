from assemblyline import odm
from assemblyline.datastore.collection import ESCollection
from assemblyline.datastore.support.build import build_mapping
from assemblyline.odm.base import MetadataValue


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


@odm.model(index=True)
class MetadataUpdate1(odm.Model):
    metadata = odm.FlattenedObject(copyto='__text__', legacy_behaviour=True)


@odm.model(index=True)
class MetadataUpdate2(odm.Model):
    metadata = odm.FlatMapping(MetadataValue(), copyto='__text__')


def test_metadata_reindex(datastore_connection):
    """Test that changing a field from keyword to wildcard doesn't break anything."""
    # Clean up from any previous runs
    collection = ESCollection(datastore_connection.ds, "metadatareindex", MetadataUpdate1, validate=False)
    collection.wipe(recreate=False)
    del collection

    # Create the collection in elastic 
    collection = ESCollection(datastore_connection.ds, "metadatareindex", MetadataUpdate1, validate=True)
    print(collection._get_index_mappings())
    collection.save("a", {
        'metadata': {
            'red': 'colour',
            'size': 106,
            'address': 'aaca.0hhe.cii1.0099.pabc',
            'bounds': {
                'top': 9.9,
                'scale': 'big',
            },
            'cats.dogs': 'treats',
            'cats.number': 1000,
        }
    })
    collection.clone_index_to('metadatareindex_backup')

    def test_original_layout(collection: ESCollection):
        collection.commit()
        properties = collection.fields()
        print(properties)
        assert properties['metadata.red']['type'] == 'keyword'
        assert not properties['metadata.red']['default']
        assert properties['metadata.size']['type'] == 'keyword'
        assert not properties['metadata.size']['default']
        assert properties['metadata.address']['type'] == 'keyword'
        assert not properties['metadata.address']['default']
        assert properties['metadata.bounds']['type'] == 'keyword'
        assert not properties['metadata.bounds']['default']
        assert properties['metadata.cats.dogs']['type'] == 'keyword'
        assert not properties['metadata.cats.dogs']['default']
        assert properties['metadata.cats.number']['type'] == 'keyword'
        assert not properties['metadata.cats.number']['default']

        docs = list(collection.stream_search("*:*", fl='id', as_obj=False))
        doc_ids = [doc['id'] for doc in docs]
        assert doc_ids == ['a']
        return properties

    properties = test_original_layout(collection)
    del collection

    # Open that same collection using the new mapping
    collection = ESCollection(datastore_connection.ds, "metadatareindex", MetadataUpdate2, validate=True)
    print(collection._get_index_mappings())

    # Check that the fields haven't changed
    properties_after = collection.fields()
    assert properties == properties_after

    # Reindex
    collection.reindex()

    # Check that the fields match the new model
    properties = collection.fields()
    print(properties)
    assert properties['metadata.red']['type'] == 'wildcard'
    assert properties['metadata.red']['default']
    assert properties['metadata.size']['type'] == 'wildcard'
    assert properties['metadata.size']['default']
    assert properties['metadata.address']['type'] == 'wildcard'
    assert properties['metadata.address']['default']
    assert properties['metadata.bounds']['type'] == 'wildcard'
    assert properties['metadata.bounds']['default']
    assert properties['metadata.cats.dogs']['type'] == 'wildcard'
    assert properties['metadata.cats.dogs']['default']
    assert properties['metadata.cats.number']['type'] == 'wildcard'
    assert properties['metadata.cats.number']['default']

    collection.delete("a")
    collection.commit()
    docs = list(collection.stream_search("*:*", fl='id', as_obj=False))
    doc_ids = [doc['id'] for doc in docs]
    assert doc_ids == []

    # Check if we can restore from backup
    collection.clone_index_from('metadatareindex_backup')
    test_original_layout(collection)
