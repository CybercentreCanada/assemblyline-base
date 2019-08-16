import sys

from assemblyline.common import forge
from assemblyline.odm.random_data import create_heuristics, create_users, create_services, create_signatures, \
    create_submission, create_alerts


class PrintLogger(object):
    def __init__(self, indent=""):
        self.indent = indent

    def info(self, msg):
        print(f"{self.indent}{msg}")

    def warn(self, msg):
        print(f"{self.indent}[W] {msg}")

    def error(self, msg):
        print(f"{self.indent}[E] {msg}")


def create_basic_data(log=None, ds=None, svc=True):
    ds = ds or forge.get_datastore()
    log.info("\nCreating user objects...")
    create_users(ds, log=log)

    if svc:
        log.info("\nCreating services...")
        create_services(ds, log=log)

    log.info("\nImporting test signatures...")
    signatures = create_signatures(ds)
    for s in signatures:
        log.info(f"\t{s}")

    if svc:
        log.info("\nCreating random heuristics...")
        create_heuristics(ds, log=log)


def create_extra_data(log=None, ds=None, fs=None):
    ds = ds or forge.get_datastore()
    fs = fs or forge.get_filestore()

    log.info("\nCreating 10 Submissions...")
    submissions = []
    for x in range(10):
        s = create_submission(ds, fs, log=log)
        submissions.append(s)

    log.info("\nCreating 50 Alerts...")
    create_alerts(ds, submission_list=submissions, log=log)


if __name__ == "__main__":
    datastore = forge.get_datastore()
    logger = PrintLogger()
    create_basic_data(log=logger, ds=datastore, svc="nosvc" not in sys.argv)
    if "full" in sys.argv:
        create_extra_data(log=logger, ds=datastore)

    logger.info("\nDone.")
