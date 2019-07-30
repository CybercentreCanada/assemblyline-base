import os
import logging

from assemblyline.common import forge
from assemblyline.common.str_utils import safe_str
from assemblyline.common.uid import get_id_from_data
from assemblyline.odm.models.signature import Signature


class SuricataImporter(object):
    def __init__(self, logger=None):
        if not logger:
            from assemblyline.common import log as al_log
            al_log.init_logging('suricata_importer')
            logger = logging.getLogger('assemblyline.suricata_importer')
            logger.setLevel(logging.INFO)

        self.ds = forge.get_datastore()
        self.classification = forge.get_classification()
        self.log = logger

    def parse_meta(self, signature):
        meta = {}
        try:
            meta_parts = signature.split("(", 1)[1].strip(" );").split("; ")
            for part in meta_parts:
                if ":" in part:
                    key, val = part.split(":", 1)
                    if key == "metadata":
                        for metadata in val.split(","):
                            meta_key, meta_val = metadata.strip().split(' ')
                            meta[meta_key] = safe_str(meta_val)
                    else:
                        meta[key] = safe_str(val.strip('"'))
        except ValueError:
            return meta

        return meta

    def _save_signatures(self, signatures, source, default_status="TESTING"):
        saved_sigs = []
        order = 1
        for signature in signatures:
            signature_hash = get_id_from_data(signature, length=16)

            meta = self.parse_meta(signature)

            classification = meta.get('classification', self.classification.UNRESTRICTED)
            signature_id = meta.get('sid', signature_hash)
            revision = meta.get('rev', 1)
            name = meta['msg']
            status = meta.get('al_status', default_status)

            key = f"suricata_{signature_id}_{revision}"

            sig = Signature({
                'classification': classification,
                "data": signature,
                "name": name,
                "order": order,
                "revision": int(revision),
                "signature_id": signature_id,
                "source": source,
                "status": status,
                "type": "suricata"
            })
            self.ds.signature.save(key, sig)
            self.log.info("Added signature %s" % name)

            saved_sigs.append(sig)
            order += 1

        return saved_sigs

    def _split_signatures(self, data):
        signatures = []
        for line in data.splitlines():
            temp_line = line.strip()

            if temp_line == "" or temp_line.startswith("#"):
                continue

            signatures.append(line)

        return signatures

    def import_data(self, yara_bin, source, default_status="TESTING"):
        return self._save_signatures(self._split_signatures(yara_bin), source, default_status=default_status)

    def import_file(self, cur_file, source=None, default_status="TESTING"):
        cur_file = os.path.expanduser(cur_file)
        if os.path.exists(cur_file):
            with open(cur_file, "r") as suricata_file:
                suricata_bin = suricata_file.read()
                return self.import_data(suricata_bin,
                                        source or os.path.basename(cur_file),
                                        default_status=default_status)
        else:
            raise Exception(f"File {cur_file} does not exists.")

    def import_files(self, files, default_status="TESTING"):
        output = {}
        for cur_file in files:
            output[cur_file] = self.import_file(cur_file, default_status=default_status)

        return output
