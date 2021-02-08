from assemblyline import odm


@odm.model(index=True, store=True)
class Statistics(odm.Model):
    count = odm.Integer(default=0)
    min = odm.Integer(default=0)
    max = odm.Integer(default=0)
    avg = odm.Integer(default=0)
    sum = odm.Integer(default=0)
    first_hit = odm.Optional(odm.Date())
    last_hit = odm.Optional(odm.Date())
