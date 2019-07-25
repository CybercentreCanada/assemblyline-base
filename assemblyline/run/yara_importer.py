import os
import logging

from assemblyline.common import forge
from assemblyline.common.str_utils import safe_str
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
        name = None
        for line in signature.splitlines():
            line = line.strip()
            if line.startswith("rule ") or line.startswith("private rule ") \
                    or line.startswith("global rule ") or line.startswith("global private rule "):
                name = line.split(":")[0].split("{")[0]
                name = name.replace("global ", "").replace("private ", "").replace("rule ", "")
                break

        return name.strip()

    def parse_meta(self, signature):
        meta = {}
        meta_started = False
        for line in signature.splitlines():
            line = line.strip()
            if not meta_started and line.startswith('meta') and line.endswith(':'):
                meta_started = True
                continue

            if meta_started:
                if line.startswith("//") or line == "":
                    continue

                if "=" not in line:
                    break

                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"')
                meta[key] = safe_str(val)


        return meta

    def _save_signatures(self, signatures, source, default_status="TESTING"):
        saved_sigs = []
        order = 0
        for signature in signatures:
            signature_hash = get_id_from_data(signature, length=16)

            meta = self.parse_meta(signature)

            classification = meta.get('classification', self.classification.UNRESTRICTED)
            signature_id = meta.get('rule_id', meta.get('signature_id', meta.get('id' , signature_hash)))
            revision = meta.get('rule_version', meta.get('revision', 1))
            name = self.get_signature_name(signature)
            status = meta.get('al_status', default_status)

            key = f"yara_{signature_id}r.{revision}"

            sig = Signature({
                'classification': classification,
                "data": signature,
                "name": name,
                "order": order,
                "revision": int(revision),
                "signature_id": signature_id,
                "source": source,
                "status": status,
                "type": "yara"
            })
            self.ds.signature.save(key, sig)
            self.log.info("Added signature %s" % name)

            saved_sigs.append(sig)
            order += 1

        return saved_sigs

    def _split_signatures(self, data):
        current_signature = []
        signatures = []
        in_rule = False
        for line in data.splitlines():
            temp_line = line.strip()

            if in_rule:
                current_signature.append(line)

                if temp_line == "}":
                    signatures.append("\n".join(current_signature))
                    current_signature = []
                    in_rule = False

            if temp_line.startswith("rule ") or temp_line.startswith("private rule ") \
                    or temp_line.startswith("global rule ") or temp_line.startswith("global private rule "):
                in_rule = True
                current_signature.append(line)

        return signatures

    def import_data(self, yara_bin, source, default_status="TESTING"):
        return self._save_signatures(self._split_signatures(yara_bin), source, default_status=default_status)

    def import_file(self, cur_file, source=None, default_status="TESTING"):
        cur_file = os.path.expanduser(cur_file)
        if os.path.exists(cur_file):
            with open(cur_file, "r") as yara_file:
                yara_bin = yara_file.read()
                return self.import_data(yara_bin, source or os.path.basename(cur_file), default_status=default_status)
        else:
            raise Exception(f"File {cur_file} does not exists.")

    def import_files(self, files, default_status="TESTING"):
        output = {}
        for cur_file in files:
            output[cur_file] = self.import_file(cur_file, default_status=default_status)

        return output
