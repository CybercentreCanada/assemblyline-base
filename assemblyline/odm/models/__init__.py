import datetime
import random
import time
import uuid

from assemblyline.odm import Boolean, Enum, Keyword, Text, List, Model, Compound, Integer, Float, Date, Mapping, \
    Classification

ALPHA = "ABCDEFGHIJKLMNOPQRSTUPVXYZabcdefghijklmnopqrstuvwxyz"
HASH_ALPHA = "abcdef0123456789"
WORDS = """The Cyber Centre stays on the cutting edge of technology by working with commercial vendors of cyber security 
technology to support their development of enhanced cyber defence tools To do this our experts survey the cyber 
security market and evaluate emerging technologies in order to determine their potential to improve cyber security 
across the country The Cyber Centre supports innovation by collaborating with all levels of government private 
industry and academia to examine complex problems in cyber security We are constantly engaging partners to promote 
an open and innovative environment We invite partners to work with us but also promote other Government of Canada 
innovation programs One of our key partnerships is with the Government of Canada Build in Canada Innovation Program 
BCIP The BCIP helps Canadian companies of all sizes transition their state of the art goods and services from the 
laboratory to the marketplace For certain cyber security innovations the Cyber Centre performs the role of technical 
authority We evaluate participating companies new technology and provide feedback in order to assist them in bringing 
their product to market To learn more about selling or testing an innovation visit the BCIP website
""".split()
META_KEYS = ["key_a", "key_b", "key_c", "key_d", "key_e", "key_f"]
EXT = [
    ".jpg",
    ".doc",
    ".exe",
    ".pdf",
    ".xls",
    ".lnk",
    ".gif",
    ".ppt"
]
DOM = [
    ".com",
    ".ca",
    ".biz",
    ".edu"
]


def get_random_word():
    return random.choice(WORDS)


def get_random_phrase(wmin=2, wmax=6):
    return " ".join([get_random_word() for _ in range(random.randint(wmin, wmax))])


def get_random_hash(hash_len):
    return "".join([random.choice(HASH_ALPHA) for _ in range(hash_len)])


def get_random_uid():
    return str(uuid.uuid4())


def get_random_filename(smin=1, smax=3):
    return "_".join([get_random_word().lower() for _ in range(random.randint(smin, smax))]) + random.choice(EXT)


def get_random_directory(smin=2, smax=6):
    return "/".join([get_random_word().lower() for _ in range(random.randint(smin, smax))])


def get_random_string(smin=4, smax=24):
    return "".join([random.choice(ALPHA) for _ in range(random.randint(smin, smax))])


def get_random_host():
    return get_random_word().lower() + random.choice(DOM)


def get_random_ip():
    return ".".join([str(random.randint(1, 254)) for _ in range(4)])


def get_random_iso_date(epoch=None):
    if epoch is None:
        epoch = time.time() + random.randint(-10000, 10000)

    return datetime.datetime.fromtimestamp(epoch).isoformat() + "Z"


def get_random_mapping(field):
    return {META_KEYS[i]: random_data_for_field(field, META_KEYS[i]) for i in range(random.randint(0, 5))}


# noinspection PyProtectedMember
def random_data_for_field(field, name):
    if isinstance(field, Boolean):
        return random.choice([True, False])
    elif isinstance(field, Classification):
        possible_classifications = list(field.engine._classification_cache)
        possible_classifications.extend([field.engine.UNRESTRICTED, field.engine.RESTRICTED])
        return random.choice(possible_classifications)
    elif isinstance(field, Enum):
        return random.choice(list(field.values))
    elif isinstance(field, List):
        return [random_data_for_field(field.child_type, name) if not isinstance(field.child_type, Model)
                else random_model_obj(field.child_type, as_json=True) for _ in range(random.randint(1, 4))]
    elif isinstance(field, Compound):
        return random_model_obj(field.child_type, as_json=True)
    elif isinstance(field, Mapping):
        return get_random_mapping(field.child_type)
    elif isinstance(field, Date):
        return get_random_iso_date()
    elif isinstance(field, Integer):
        return random.randint(128, 4096)
    elif isinstance(field, Float):
        return random.randint(12800, 409600) / 100.0
    elif isinstance(field, Keyword):
        if name:
            if "sha256" in name:
                return get_random_hash(64)
            elif "sid" in name:
                return get_random_uid()
            elif "mac" in name:
                return get_random_hash(12)
            elif "sha1" in name:
                return get_random_hash(40)
            elif "md5" in name or "scan_key" in name:
                return get_random_hash(32)
            elif "host" in name or "node" in name:
                return get_random_host()
            elif name.endswith("ip"):
                return get_random_ip()
            elif "file" in name:
                return get_random_filename()
            elif "directory" in name:
                return get_random_directory()

        return get_random_word()
    elif isinstance(field, Text):
        return get_random_phrase(wmin=4, wmax=40)
    else:
        raise ValueError(f"Unknown field type: {field}")


# noinspection PyProtectedMember
def random_model_obj(model, as_json=False):
    data = {}
    for f_name, f_value in model._odm_field_cache.items():
        data[f_name] = random_data_for_field(f_value, f_name)

    if as_json:
        return data
    else:
        return model(data)
