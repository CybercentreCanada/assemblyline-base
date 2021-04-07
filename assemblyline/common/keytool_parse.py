import re
from subprocess import Popen, PIPE, call
from assemblyline.common.str_utils import safe_str

class Certificate():
    def __init__(self):
        self.raw = ""
        self.issuer = ""
        self.owner = ""
        self.country = ""
        self.valid_from = ""
        self.valid_to = ""

def keytool_printcert(cert_path: str):
    stdout, stderr = Popen(["keytool", "-printcert", "-file", cert_path],
                                stderr=PIPE, stdout=PIPE).communicate()
    stdout = safe_str(stdout)

    if stdout:
        if "keytool error" not in stdout:
            return stdout

    return None

def certificate_chain_from_printcert(printcert: str):
    certs = []

    for cert_str in  re.split('Certificate\[\d+\]:', printcert): # split printcert output incase of certificate chain
        if cert_str == '':
            continue
        cert = Certificate()
        cert.raw = cert_str.strip()
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