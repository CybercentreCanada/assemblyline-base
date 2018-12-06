import os

from assemblyline import odm


@odm.model(index=True, store=True)
class FakeResultSection(odm.Model):
    title = odm.Text()
    score = odm.Integer()
    body = odm.Text()


@odm.model(index=True, store=True)
class FakeFileObject(odm.Model):
    size = odm.Integer()
    hash = odm.Keyword()
    name = odm.Text()


@odm.model(index=True, store=True)
class FakeSubmission(odm.Model):
    yml_config = os.path.join(os.path.dirname(__file__).replace("datastore/bench", "test"), "classification.yml")

    classification = odm.Classification(default="UNRESTRICTED", yml_config=yml_config)
    submission_type = odm.Enum({"live", "user", "client"})
    description = odm.Text(copyto='text', default="Default scan of a random file!")
    max_score = odm.Integer()

    start_time = odm.Date()
    end_time = odm.Date()

    tags = odm.List(odm.Keyword(), default=[], copyto='text')

    results = odm.List(odm.Compound(FakeResultSection), default=[])

    files = odm.List(odm.Compound(FakeFileObject), default=[])

    metadata = odm.Mapping(odm.Text(), default={})
