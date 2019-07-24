import os
import logging

from assemblyline.common import forge
from assemblyline.common.uid import get_id_from_data
from assemblyline.odm.models.signature import Signature


class YaraImporter(object):
    def __init__(self, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('yara_importer')
            logger = logging.getLogger('assemblyline.yara_importer')
            logger.setLevel(logging.INFO)

        self.ds = forge.get_datastore()
        self.classification = forge.get_classification()
        self.log = logger


    def get_signature_name(self, signature):
        # TODO: extract the signature name
        return ""


    def parse_meta(self, signature):
        # TODO: extract all the meta key/value pairs
        return {}


    def _save_signatures(self, signatures, source):
        saved_sigs = []
        for signature in signatures:
            meta = self.parse_meta(signature)

            classification = meta.get('classification', self.classification.UNRESTRICTED)
            signature_id = meta.get('rule_id', meta.get('signature_id', meta.get('id' , None)))
            revision = meta.get('rule_version', meta.get('revision', 1))
            name = self.get_signature_name(signature)
            status = meta.get('al_status', 'TESTING')

            if signature_id and revision:
                key = f"yara_{signature_id}r.{revision}"
            else:
                key = get_id_from_data(signature, prefix="yara", length=16)

            sig = Signature({
                'classification': classification,
                "data": signature,
                "name": name,
                "order": 0,
                "revision": revision,
                "signature_id": signature_id,
                "source": source,
                "status": status,
                "type": "yara"
            })
            self.ds.signature.save(key, sig)
            self.log.info("Added signature %s" % name)

            saved_sigs.append(sig)

        return saved_sigs

    def _split_signatures(self, data):
        current_signature = []
        signatures = []
        in_rule = False
        for line in data.splitlines():
            if line.startswith("rule ") or line.startswith("private rule ") \
                    or line.startswith("global rule ") or line.startswith("global private rule "):
                if in_rule:
                    signatures.append("\n".join(current_signature))
                    current_signature = []
                else:
                    in_rule = True

            current_signature.append(line)

        signatures.append("\n".join(current_signature))

        return signatures


    def import_data(self, yara_bin, source):
        return self._save_signatures(self._split_signatures(yara_bin), source)


    def import_file(self, cur_file, source=None):
        cur_file = os.path.expanduser(cur_file)
        if os.path.exists(cur_file):
            with open(cur_file, "r") as yara_file:
                yara_bin = yara_file.read()
                return self.import_data(yara_bin, source or os.path.basename(cur_file))
        else:
            raise Exception(f"File {cur_file} does not exists.")

    def import_files(self, files):
        output = {}
        for cur_file in files:
            output[cur_file] = self.import_file(cur_file)

        return output
