import os
import re
import time
from subprocess import Popen, PIPE, call
from assemblyline.common.str_utils import safe_str

class Certificate():

    def __init__(self):
        self.issuer = ""
        self.owner = ""
        self.country = ""
        self.valid_from = ""
        self.valid_to = ""
        self.valid_year_end = 0
        self.valid_year_start = 0
        self.valid_until_date = time.time()

    @staticmethod
    def keytool_printcert(cert_path: str):
        stdout, stderr = Popen(["keytool", "-printcert", "-file", cur_file],
                                    stderr=PIPE, stdout=PIPE).communicate()
        stdout = safe_str(stdout)

        if stdout:
            if "keytool error" not in stdout:
                return stdout

        return None

    @staticmethod
    def certificate_chain_from_keytool(printcert: str):
        certs = []

        for cert_str in  re.split('Certificate\[\d+\]:', printcert): # split printcert output incase of certificate chain
            if cert_str == '':
                continue
            cert = Certificate()
            for line in cert_str.splitlines():
                if "Owner:" in line:
                    cert.owner = line.split(": ", 1)[1]
                    country = cert.owner.split("C=")
                    if len(country) != 1:
                        cert.country = country[1]

                if "Issuer:" in line:
                    cert.issuer = line.split(": ", 1)[1]

                if "Valid from:" in line:
                    cert.valid_from = line.split(": ", 1)[1].split(" until:")[0]
                    cert.valid_to = line.rsplit(": ", 1)[1]

            certs.append(cert)

        return certs