from assemblyline import odm

MATCH_TYPES = ['match', 'regex']


@odm.model(index=True, store=True)
class TagSafelist(odm.Model):
    added = odm.Date(default="NOW")            # Date when the tag was added to the safelist
    added_by = odm.Keyword()                   # User who added the tag to the safelist
    match_type = odm.Enum(values=MATCH_TYPES)  # Type of match used for the test
    type = odm.Keyword()                       # Type of tag that will be tested
    value = odm.Keyword()                      # Regex or direct value to match to
    updated = odm.Date(default="NOW")          # Last date when the safelisted item was modified
    updated_by = odm.Keyword()                 # Last user who modified the safelisted item


if __name__ == "__main__":
    from pprint import pprint
    from assemblyline.odm.randomizer import random_model_obj
    pprint(random_model_obj(TagSafelist, as_json=True))
