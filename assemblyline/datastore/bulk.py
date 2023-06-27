import json
import typing
from copy import deepcopy


class ElasticBulkPlan(object):
    def __init__(self, indexes: typing.List[str], model: typing.Optional[type] = None):
        self.indexes = indexes
        self.model = model
        self.operations: typing.List[str] = []

    @property
    def empty(self):
        return len(self.operations) == 0

    def add_delete_operation(self, doc_id, index=None):
        if index:
            self.operations.append(json.dumps({"delete": {"_index": index, "_id": doc_id}}))
        else:
            for cur_index in self.indexes:
                self.operations.append(json.dumps({"delete": {"_index": cur_index, "_id": doc_id}}))

    def add_insert_operation(self, doc_id, doc, index=None):
        if self.model and isinstance(doc, self.model):
            saved_doc = doc.as_primitives(hidden_fields=True)
        elif self.model:
            saved_doc = self.model(doc).as_primitives(hidden_fields=True)
        else:
            if not isinstance(doc, dict):
                saved_doc = {'__non_doc_raw__': doc}
            else:
                saved_doc = deepcopy(doc)
        saved_doc['id'] = doc_id

        self.operations.append(json.dumps({"create": {"_index": index or self.indexes[0], "_id": doc_id}}))
        self.operations.append(json.dumps(saved_doc))

    def add_upsert_operation(self, doc_id, doc, index=None):
        if self.model and isinstance(doc, self.model):
            saved_doc = doc.as_primitives(hidden_fields=True)
        elif self.model:
            saved_doc = self.model(doc).as_primitives(hidden_fields=True)
        else:
            if not isinstance(doc, dict):
                saved_doc = {'__non_doc_raw__': doc}
            else:
                saved_doc = deepcopy(doc)
        saved_doc['id'] = doc_id

        self.operations.append(json.dumps({"update": {"_index": index or self.indexes[0], "_id": doc_id}}))
        self.operations.append(json.dumps({"doc": saved_doc, "doc_as_upsert": True}))

    def add_update_operation(self, doc_id, doc, index=None):

        if self.model and isinstance(doc, self.model):
            saved_doc = doc.as_primitives(hidden_fields=True)
        elif self.model:
            saved_doc = self.model(doc, mask=list(doc.keys())).as_primitives(hidden_fields=True)
        else:
            if not isinstance(doc, dict):
                saved_doc = {'__non_doc_raw__': doc}
            else:
                saved_doc = deepcopy(doc)

        if index:
            self.operations.append(json.dumps({"update": {"_index": index, "_id": doc_id}}))
            self.operations.append(json.dumps({"doc": saved_doc}))
        else:
            for cur_index in self.indexes:
                self.operations.append(json.dumps({"update": {"_index": cur_index, "_id": doc_id}}))
                self.operations.append(json.dumps({"doc": saved_doc}))

    def get_plan_data(self):
        return "\n".join(self.operations)
