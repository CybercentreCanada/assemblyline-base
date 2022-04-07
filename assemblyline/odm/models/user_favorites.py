from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


@odm.model(index=False, store=False, description="Abstract Model of Favorite")
class Favorite(odm.Model):
    created_by = odm.Keyword(description="Who created the favorite")
    classification = odm.Classification(is_user_classification=True, copyto="__text__",
                                        default=Classification.UNRESTRICTED,
                                        description="Classification of the favorite")
    name = odm.Keyword(description="Name of the favorite")
    query = odm.Keyword(description="Query for the favorite")


@odm.model(index=False, store=False, description="Model of User Favorites")
class UserFavorites(odm.Model):
    alert = odm.List(odm.Compound(Favorite), default=[], description="Alert page favorites")
    error = odm.List(odm.Compound(Favorite), default=[], description="Error page favorites")
    search = odm.List(odm.Compound(Favorite), default=[], description="Search page favorites")
    signature = odm.List(odm.Compound(Favorite), default=[], description="Signature page favorites")
    submission = odm.List(odm.Compound(Favorite), default=[], description="Submission page favorites")
