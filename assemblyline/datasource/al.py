from assemblyline.common import forge
from assemblyline.datasource.common import Datasource

Classification = forge.get_classification()


class AL(Datasource):
    def __init__(self, log, **kw):
        super(AL, self).__init__(log, **kw)
        self.datastore = forge.get_datastore()

    def parse(self, results, **kw):
        return results

    def query(self, value, **kw):
        results = []

        hash_type = self.hash_type(value)

        query = "%s:%s OR %s:%s" % (
            hash_type, value.lower(), hash_type, value.upper()
        )

        res = self.datastore.file.search(query, rows=5, access_control=kw['access_control'], as_obj=False)

        for r in res['items']:
            score = 0
            score_map = {}

            res = self.datastore.result.grouped_search("response.service_name", f"id:{r['sha256']}*",
                                                       fl="result.score,id", rows=100, sort="created desc",
                                                       access_control=kw["access_control"], as_obj=False)

            for group in res['items']:
                service_name = group['value']
                for doc in group['items']:
                    score_map[service_name] = doc['result']['score']
                    score += doc['result']['score']

            result = {
                "classification": r['classification'],
                "confirmed": score >= 2000 or score < -499,
                "data": {
                    "classification": r['classification'],
                    "md5": r['md5'],
                    "sha1": r['sha1'],
                    "sha256": r['sha256'],
                    "size": r['size'],
                    "type": r['type'],
                    "seen": {
                        "count": r['seen']['count'],
                        "last": r['seen']['last']
                    },
                    "score": score,
                    "score_map": score_map
                },
                "description": "File found in AL with score of %s." % score,
                "malicious": score >= 1000,
            }

            results.append(result)

        return results
