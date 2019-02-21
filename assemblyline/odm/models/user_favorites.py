from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


@odm.model(index=False, store=False)
class Favorite(odm.Model):
    created_by = odm.Keyword()                           # Who created the favorite
    classification = odm.Classification(
        is_user_classification=True, copyto="__text__",
        default=Classification.UNRESTRICTED)             # Classification of the favorite
    name = odm.Keyword()                                 # Name of the favorite
    query = odm.Keyword()                                # Query for the favorite


@odm.model(index=False, store=False)
class UserFavorites(odm.Model):
    alert = odm.List(odm.Compound(Favorite), default=[])       # Alert page favorites
    error = odm.List(odm.Compound(Favorite), default=[])       # Error page favorites
    search = odm.List(odm.Compound(Favorite), default=[])      # Search page favorites
    signature = odm.List(odm.Compound(Favorite), default=[])   # Signature page favorites
    submission = odm.List(odm.Compound(Favorite), default=[])  # Submission page favorites
