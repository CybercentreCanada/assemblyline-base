import hashlib
import json
import os
import random

from assemblyline.common import forge
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.security import get_password_hash
from assemblyline.common.uid import get_random_id
from assemblyline.common.version import FRAMEWORK_VERSION, SYSTEM_VERSION, BUILD_MINOR
from assemblyline.odm.models.alert import Alert, Event, STATUSES, PRIORITIES
from assemblyline.odm.models.badlist import Badlist
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.ontology import ResultOntology
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service, UpdateSource
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.user import TYPES, User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.models.safelist import Safelist
from assemblyline.odm.models.workflow import Workflow
from assemblyline.odm.randomizer import SERVICES, get_random_hash, random_minimal_obj, random_model_obj, \
    get_random_phrase, get_random_uri, get_random_word
from assemblyline.run.suricata_importer import SuricataImporter
from assemblyline.run.yara_importer import YaraImporter
from assemblyline.datastore.helper import AssemblylineDatastore

full_file_list = []
classification = forge.get_classification()


class NullLogger(object):
    def info(self, msg):
        pass

    def warn(self, msg):
        pass

    def error(self, msg):
        pass

    def exception(self, msg):
        pass

    def warning(self, msg):
        pass


def create_alerts(ds, alert_count=50, submission_list=None, log=None, workflows=[]):
    for _ in range(alert_count):
        a: Alert = random_model_obj(Alert)
        a.expiry_ts = now_as_iso(60 * 60 * 24 * 14)
        if isinstance(submission_list, list):
            submission = random.choice(submission_list)
            a.file.sha256 = submission.files[0].sha256
            a.sid = submission.sid

        a.owner = random.choice(['admin', 'user', 'other', None])
        if workflows:
            def generate_workflow_event(wf) -> Event:
                event: Event = random_minimal_obj(Event)
                if random.randint(0, 1) == 0:
                    # Overwrite with workflow information
                    event.entity_type = 'workflow'
                    event.entity_name = wf.name
                    event.entity_id = wf.workflow_id
                else:
                    # Overwrite with user information
                    event.entity_type = 'user'
                    event.entity_id = get_random_word()
                event.labels = [get_random_word() for _ in range(random.randint(0, 20))]
                event.status = random.choice(list(STATUSES) + [None])
                event.priority = random.choice(list(PRIORITIES) + [None])
                return event
            a.events = [generate_workflow_event(random.choice(workflows)) for _ in range(random.randint(0, 5))]

        # Clear sub-types
        for data_type in a.al.detailed.fields():
            if data_type in ['attrib']:
                continue
            for item in a.al.detailed[data_type]:
                item['subtype'] = None

        # Generate matching detailed IPs
        ips = []
        for ip in a.al.ip_static:
            ips.append(dict(subtype=None, type='network.static.ip', value=ip,
                            verdict=random.choice(['info', 'suspicious', 'malicious'])))
        for ip in a.al.ip_dynamic:
            ips.append(dict(subtype=None, type='network.dynamic.ip', value=ip,
                            verdict=random.choice(['info', 'suspicious', 'malicious'])))
        a.al.detailed.ip = ips
        a.al.ip = [ip['value'] for ip in ips]

        # Generate matching detailed Domains
        domains = []
        for dom in a.al.domain_static:
            domains.append(dict(subtype=None, type='network.static.domain', value=dom,
                                verdict=random.choice(['info', 'suspicious', 'malicious'])))
        for dom in a.al.domain_dynamic:
            domains.append(dict(subtype=None, type='network.dynamic.domain', value=dom,
                                verdict=random.choice(['info', 'suspicious', 'malicious'])))
        a.al.detailed.domain = domains
        a.al.domain = [domain['value'] for domain in domains]

        # Generate matching detailed URIs
        uris = []
        for uri in a.al.uri_static:
            uris.append(dict(subtype=None, type='network.static.uri', value=uri,
                             verdict=random.choice(['info', 'suspicious', 'malicious'])))
        for uri in a.al.uri_dynamic:
            uris.append(dict(subtype=None, type='network.dynamic.uri', value=uri,
                             verdict=random.choice(['info', 'suspicious', 'malicious'])))
        a.al.detailed.uri = uris
        a.al.uri = [uri['value'] for uri in uris]

        ds.alert.save(a.alert_id, a)
        if log:
            log.info(f"\t{a.alert_id}")

    ds.alert.commit()


def create_heuristics(ds, log=None):
    for srv in SERVICES.keys():
        for x in range(5):
            h = random_model_obj(Heuristic)
            h.heur_id = f"{srv.upper()}.{x + 1}"
            h.name = get_random_phrase()
            ds.heuristic.save(h.heur_id, h)
            if log:
                log.info(f'\t{h.heur_id}')

    ds.heuristic.commit()


def create_services(ds: AssemblylineDatastore, log=None, limit=None):
    if not limit:
        limit = len(SERVICES)

    for svc_name, svc in list(SERVICES.items())[:limit]:
        service_data = {
            "name": svc_name,
            "enabled": True,
            "category": svc[0],
            "stage": svc[1],
            "version": f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}.1",
            "docker_config": {
                "image": f"cccs/alsvc_{svc_name.lower()}:latest",
            },
        }

        if random.choice([True, False]):
            service_data['update_config'] = {
                "sources": [random_model_obj(UpdateSource)],
                "update_interval_seconds": 600,
                "generates_signatures": True
            }

        service_data = Service(service_data)
        for x in range(4):
            # Save the same service as v4
            service_data.version = f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}.{x+1}"
            ds.service.save(f"{service_data.name}_{service_data.version}", service_data)

        # Save the default delta entry
        ds.service_delta.save(service_data.name, {"version": service_data.version})
        if log:
            log.info(f'\t{svc_name}')

    ds.service_delta.commit()
    ds.service.commit()


def create_signatures(ds):
    yara = YaraImporter(logger=NullLogger())
    suricata = SuricataImporter(logger=NullLogger())
    signatures = yara.import_file(get_yara_sig_path(), source="YAR_SAMPLE", default_status="DEPLOYED")
    signatures.extend(suricata.import_file(get_suricata_sig_path(), source="ET_SAMPLE", default_status="DEPLOYED"))

    ds.signature.commit()

    return [s['name'] for s in signatures]


def _create_errors_for_file(ds, f, services_done, log=None):
    e_list = []
    for _ in range(random.randint(0, 1)):
        e = random_model_obj(Error)
        e.expiry_ts = now_as_iso(60 * 60 * 24 * 14)

        # Only one error per service per file
        while e.response.service_name in services_done:
            e.response.service_name = random.choice(list(SERVICES.keys()))
        services_done.append(e.response.service_name)

        # Set the sha256
        e.sha256 = f

        e_key = e.build_key()
        e_list.append(e_key)
        if log:
            log.info(f"\t\t\t{e_key}")
        ds.error.save(e_key, e)

    return e_list


def _create_results_for_file(ds, fs, f, possible_childs=None, log=None):
    r_list = []
    services_done = []
    section_body_format = ["TEXT", "MEMORY_DUMP", "GRAPH_DATA", "URL", "JSON", "KEY_VALUE"]
    section_depth_list = [[1, 1, 2, 3, 1], [1, 2, 1], [1, 2, 3, 1], [1, 2]]
    section_depth = random.choice(section_depth_list)
    for _ in range(random.randint(2, 5)):
        r = random_model_obj(Result)
        r.expiry_ts = now_as_iso(60 * 60 * 24 * 14)

        # Only one result per service per file
        while r.response.service_name in services_done:
            r.response.service_name = random.choice(list(SERVICES.keys()))

        for depth_id, section in enumerate(r.result.sections):
            section.depth = section_depth[depth_id % len(section_depth)]
            section.body_format = random.choice(section_body_format)
            section.heuristic.heur_id = random.choice([f"{r.response.service_name.upper()}.{x+1}" for x in range(5)])
            if section.body_format == "GRAPH_DATA":
                cmap_min = 0
                cmap_max = random.choice([5, 10, 20])
                color_map_data = {
                    'type': 'colormap',
                    'data': {
                        'domain': [cmap_min, cmap_max],
                        'values': [random.random() * cmap_max for _ in range(50)]
                    }
                }
                section.body = json.dumps(color_map_data)
            elif section.body_format == "URL":
                data = [{"url": get_random_uri()} for _ in range(random.randint(1, 4))]
                section.body = json.dumps(data)
            elif section.body_format in ["JSON", "KEY_VALUE"]:
                data = {get_random_word(): get_random_id() for _ in range(random.randint(3, 9))}
                section.body = json.dumps(data)

        services_done.append(r.response.service_name)

        # Set the sha256
        r.sha256 = f

        if random.randint(1, 10) > 8:
            # Generate and empty result
            r_key = f"{r.build_key()}.e"
            er = random_model_obj(EmptyResult)
            er.expiry_ts = now_as_iso(60 * 60 * 24 * 14)
            ds.emptyresult.save(r_key, er)
        else:
            r_key = r.build_key()
            # Set random extracted files that are not top level
            if not possible_childs:
                r.response.extracted = []
            else:
                for e in r.response.extracted:
                    e.sha256 = random.choice(possible_childs)

            # Set random supplementary files that are not top level
            if r.response.supplementary:
                # Edit the first file to be an ontology file
                s = r.response.supplementary[0]

                # Create a random ontology
                onto = random_minimal_obj(ResultOntology).as_primitives(strip_null=True)
                onto['file']['sha256'] = f
                onto['service'] = {
                    'name': r.response.service_name,
                    'version': r.response.service_version,
                    'tool_version': r.response.service_tool_version
                }

                # Create it's file record
                supp_file = random_model_obj(File)
                supp_file.expiry_ts = now_as_iso(60 * 60 * 24 * 14)
                byte_str = json.dumps(onto).encode('utf-8')
                sha256 = hashlib.sha256(byte_str).hexdigest()
                supp_file.sha256 = sha256
                ds.file.save(sha256, supp_file)
                fs.put(sha256, byte_str)

                # Add the random files
                s.sha256 = sha256
                s.name = "random.ontology"
                s.description = f"Random Ontology file for: {f}"

                r.response.supplementary = [s]

            ds.result.save(r_key, r)

        if log:
            log.info(f"\t\t\t{r_key}")
        r_list.append(r_key)

    return r_list


def create_submission(ds, fs, log=None):
    f_list = []
    r_list = []
    e_list = []

    first_level_files = []
    s = random_model_obj(Submission)
    s.expiry_ts = now_as_iso(60 * 60 * 24 * 14)

    if log:
        log.info(f"\t{s.sid}")
        log.info("\tGenerating files for submission...")
    for _ in range(random.randint(3, 6)):
        f = random_model_obj(File)
        f.expiry_ts = now_as_iso(60 * 60 * 24 * 14)
        byte_str = get_random_phrase(wmin=8, wmax=20).encode()
        sha256 = hashlib.sha256(byte_str).hexdigest()
        f.sha256 = sha256
        ds.file.save(sha256, f)
        fs.put(sha256, byte_str)

        if log:
            log.info(f"\t\t{sha256}")

        f_list.append(sha256)

    for _ in range(random.randint(1, 2)):
        first_level_files.append(f_list.pop())

    if log:
        log.info("\t\tGenerating results and errors for top level files...")
    for f in first_level_files:
        r_list.extend(_create_results_for_file(ds, fs, f, possible_childs=f_list, log=log))
        e_list.extend(_create_errors_for_file(ds, f, [x.split('.')[1] for x in r_list if x.startswith(f)], log=log))

    if log:
        log.info("\t\tGenerating results and errors for children files...")
    for f in f_list:
        r_list.extend(_create_results_for_file(ds, fs, f, log=log))
        e_list.extend(_create_errors_for_file(ds, f, [x.split('.')[1] for x in r_list if x.startswith(f)], log=log))

    s.results = r_list
    s.errors = e_list

    s.error_count = len(e_list)
    s.file_count = len({x[:64] for x in r_list})

    s.files = s.files[:len(first_level_files)]

    fid = 0
    for f in s.files:
        f.sha256 = first_level_files[fid]
        fid += 1

    s.params.psid = None
    s.state = 'completed'

    if log:
        log.info(f'{s}')

    ds.submission.save(s.sid, s)

    ds.emptyresult.commit()
    ds.error.commit()
    ds.file.commit()
    ds.result.commit()
    ds.submission.commit()

    return s


def create_users(ds, log=None):
    admin_pass = os.getenv("DEV_ADMIN_PASS", 'admin') or 'admin'
    user_pass = os.getenv("DEV_USER_PASS", 'user') or 'user'
    user_data = User({
        "agrees_with_tos": "NOW",
        "apikeys": {'devkey': {'acl': ["R", "W"], "password": get_password_hash(admin_pass)}},
        "classification": classification.RESTRICTED,
        "name": "Administrator",
        "email": "admin@assemblyline.cyber.gc.ca",
        "password": get_password_hash(admin_pass),
        "uname": "admin",
        "type": [TYPES.admin]})
    ds.user.save('admin', user_data)
    ds.user_settings.save('admin', UserSettings({"ignore_cache": True, "deep_scan": True}))
    if log:
        log.info(f"\tU:{user_data.uname}   P:{admin_pass}")

    user_data = User({
        "name": "User",
        "email": "user@assemblyline.cyber.gc.ca",
        "apikeys": {'devkey': {'acl': ["R", "W"], "password": get_password_hash(user_pass)}},
        "password": get_password_hash(user_pass),
        "uname": "user",
        "type": [TYPES.user]})
    ds.user.save('user', user_data)
    ds.user_settings.save('user', UserSettings())
    if log:
        log.info(f"\tU:{user_data.uname}   P:{user_pass}")

    ds.user.commit()


def create_badlists(ds, log=None):
    for _ in range(20):
        sl = random_model_obj(Badlist, as_json=True)
        if sl['type'] == 'file':
            sl.pop('tag', None)
        elif sl['type'] == 'tag':
            sl.pop('file', None)
        sl['hashes']['sha256'] = "0" + get_random_hash(63)
        ds.badlist.save(sl['hashes']['sha256'], sl)
        if log:
            log.info(f"\t{sl['hashes']['sha256']}")

    ds.badlist.commit()


def create_safelists(ds, log=None):
    for _ in range(20):
        sl = random_model_obj(Safelist, as_json=True)
        if sl['type'] == 'file':
            sl.pop('tag', None)
        elif sl['type'] == 'tag':
            sl.pop('file', None)
        sl['hashes']['sha256'] = "0" + get_random_hash(63)
        ds.safelist.save(sl['hashes']['sha256'], sl)
        if log:
            log.info(f"\t{sl['hashes']['sha256']}")

    ds.safelist.commit()


def create_workflows(ds, log=None):
    workflows = []
    for _ in range(20):
        w_id = get_random_id()
        workflow = random_model_obj(Workflow)
        workflow.workflow_id = w_id
        ds.workflow.save(w_id, workflow)
        if log:
            log.info(f'\t{w_id}')
        workflows.append(workflow)

    ds.workflow.commit()
    return workflows


def get_suricata_sig_path():
    for (d, _, filenames) in os.walk(__file__[:-11]):
        for f in filenames:
            if f == 'sample_suricata.rules':
                return os.path.join(d, f)

    raise Exception('Could not find suricata sample file...')


def get_yara_sig_path():
    for (d, _, filenames) in os.walk(__file__[:-11]):
        for f in filenames:
            if f == 'sample_rules.yar':
                return os.path.join(d, f)

    raise Exception('Could not find yara sample file...')


def wipe_alerts(ds):
    ds.alert.wipe()


def wipe_heuristics(ds):
    ds.heuristic.wipe()


def wipe_services(ds):
    ds.service.wipe()
    ds.service_delta.wipe()


def wipe_signatures(ds):
    ds.signature.wipe()


def wipe_submissions(ds, fs):
    ds.error.wipe()
    ds.file.wipe()
    ds.emptyresult.wipe()
    ds.result.wipe()
    ds.submission.wipe()
    ds.submission_summary.wipe()
    ds.submission_tree.wipe()

    for f in full_file_list:
        fs.delete(f)


def wipe_users(ds):
    ds.user.wipe()
    ds.user_settings.wipe()
    ds.user_avatar.wipe()
    ds.user_favorites.wipe()


def wipe_safelist(ds):
    ds.safelist.wipe()


def wipe_badlist(ds):
    ds.badlist.wipe()


def wipe_workflows(ds):
    ds.workflow.wipe()


def wipe_all_except_users(ds, fs):
    wipe_alerts(ds)
    wipe_badlist(ds)
    wipe_heuristics(ds)
    wipe_services(ds)
    wipe_signatures(ds)
    wipe_submissions(ds, fs)
    wipe_safelist(ds)
    wipe_workflows(ds)
