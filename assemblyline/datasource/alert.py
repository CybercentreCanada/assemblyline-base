from assemblyline.common import forge
from assemblyline.datasource.common import Datasource

Classification = forge.get_classification()


class Alert(Datasource):
    def __init__(self, log, **kw):
        super(Alert, self).__init__(log, **kw)
        self.datastore = forge.get_datastore()

    def parse(self, results, **kw):
        return results

    def query(self, value, **kw):
        hash_type = self.hash_type(value)

        query = "file.%s:%s OR file.%s:%s" % (
            hash_type, value.lower(), hash_type, value.upper()
        )

        res = self.datastore.alert.search(query, rows=5, sort="al.score desc",
                                           access_control=kw['access_control'], as_obj=False)

        count = res['total']
        if count <= 0:
            return []

        data = []
        item = {
            "confirmed": False,
            "data": data,
            "description": "Alerted on %s times" % str(count),
            "malicious": False,
        }

        for r in res['items']:
            score = r['al']['score']
            if score >= 500:
                item['malicious'] = True
            if score >= 2000 or score <= -100:
                item['confirmed'] = True

            data.append({
                "classification": r['classification'],
                "date": r['reporting_ts'],
                "id": r['id'],
                "score": r['al']['score'],
            })

        return [item]
