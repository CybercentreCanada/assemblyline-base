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

        res = self.datastore.files.search(query, rows=5, access_control=kw['access_control'])

        for r in res['items']:
            score = 0
            score_map = {}

            res = self.datastore.results.group("%s:%s*" % (self.datastore.ID, r['sha256']), ["response.service_name"],
                                               fields="result.score,%s" % self.datastore.ID, rows=100,
                                               sort="created desc", access_control=kw["access_control"])

            for group in res['response.service_name']:
                for doc in group['items']:
                    service_name = doc[self.datastore.ID][65:].split(".", 1)[0]
                    if service_name != "HashSearch":
                        score_map[service_name] = doc['result.score']
                        score += doc['result.score']

            result = {
                "classification": r['classification'],
                "confirmed": score >= 2000 or score < -499,
                "data": {
                    "classification": r['classification'],
                    "md5": r['md5'],
                    "sha1": r['sha1'],
                    "sha256": r['sha256'],
                    "size": r['size'],
                    "tag": r['tag'],
                    "seen_count": r['seen_count'],
                    "seen_last": r['seen_last'],
                    "score": score,
                    "score_map": score_map
                },
                "description": "File found in AL with score of %s." % score,
                "malicious": score >= 1000,
            }

            results.append(result)

        return results
