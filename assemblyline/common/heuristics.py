from assemblyline.common import forge

Classification = forge.get_classification()


class InvalidClassificationException(Exception):
    pass


class Heuristic(object):
    def __init__(self, heur_id, name, filetype, description, classification=Classification.UNRESTRICTED):
        self.heur_id = heur_id
        self.name = name
        self.filetype = filetype
        self.description = description
        self.classification = classification
        if not Classification.is_valid(classification):
            raise InvalidClassificationException()

    def __repr__(self):
        return "Heuristic('{id}', '{name}', '{filetype}', " \
               "'{description}', '{classification}')".format(id=self.heur_id, name=self.name,
                                                             filetype=self.filetype, description=self.description,
                                                             classification=self.classification)

    def to_dict(self):
        return {
            "heur_id": self.heur_id,
            "name": self.name,
            "filetype": self.filetype,
            "description": self.description.strip(),
            "classification": self.classification
        }


def get_heuristics_form_class(cls):
    out = []
    try:
        for c_cls in list(cls.__mro__)[:-1][::-1]:
            out.extend([v for v in c_cls.__dict__.itervalues() if isinstance(v, Heuristic) and v not in out])
    except AttributeError:
        pass

    return sorted(out, key=lambda k: k.id)
