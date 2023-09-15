from assemblyline import odm


@odm.model(index=True, store=True, description="Statistics Model")
class Statistics(odm.Model):
    count = odm.Integer(default=0, description="Count of statistical hits")
    min = odm.Integer(default=0, description="Minimum value of all stastical hits")
    max = odm.Integer(default=0, description="Maximum value of all stastical hits")
    avg = odm.Integer(default=0, description="Average of all stastical hits")
    sum = odm.Integer(default=0, description="Sum of all stastical hits")
    first_hit = odm.Optional(odm.Date(), description="Date of first hit of statistic")
    last_hit = odm.Optional(odm.Date(), description="Date of last hit of statistic")
