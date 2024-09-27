from assemblyline import odm


@odm.model(index=True, store=True, description="""The Statistics model within Assemblyline is a framework that gathers and organizes quantitative data from malware analysis. It offers users essential statistical information such as counts, minimum and maximum values, averages, and sums. These data points help to quantify different attributes of the analyzed events or items.

In addition, the model includes fields that track the timing of events, such as when a particular signature was first seen or most recently seen. This information can be beneficial for tracking trends and patterns over time.

By utilizing the Statistics model, users are equipped with the necessary data to perform searches and analyze malware using Lucene queries. This can aid in the efficient identification and examination of cyber threats.
""")
class Statistics(odm.Model):
    count = odm.Integer(default=0, description="Total number of times a particular data point or event has been recorded.")
    min = odm.Integer(default=0, description="The smallest numerical value recorded among all statistical events.")
    max = odm.Integer(default=0, description="The largest numerical value recorded among all statistical events.")
    avg = odm.Integer(default=0, description="The mean value derived from the sum of all recorded statistical events divided by the count.")
    sum = odm.Integer(default=0, description="The aggregate total of all numerical values from the statistical events.")
    first_hit = odm.Optional(odm.Date(), description="The date when the first recorded instance of the statistical event occurred.")
    last_hit = odm.Optional(odm.Date(), description="The date when the most recent instance of the statistical event was recorded.")
