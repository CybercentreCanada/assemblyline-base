
import random

import datetime
import time

from assemblyline.datastore.bench.model import FakeFileObject, FakeResultSection, FakeSubmission
from hashlib import sha256

ALPHA = "ABCDEFGHIJKLMNOPQRSTUPVXYZabcdefghijklmnopqrstuvwxyz"
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


def get_random_file(as_model=True):
    size = random.randint(214, 7373649)
    name = get_random_filename()
    file_hash = sha256(name.encode()).hexdigest()
    out = {
        "size": size,
        "name": name,
        "hash": file_hash
    }
    if as_model:
        return FakeFileObject(out)
    return out


def get_random_result_section(as_model=True):
    title = get_random_phrase()
    score = random.randint(0, 1000)
    body = ". ".join([get_random_phrase(4, 20) for _ in range(random.randint(1, 6))])

    out = {
        "title": title,
        "score": score,
        "body": body
    }
    if as_model:
        return FakeResultSection(out)
    return out


def get_random_submission(as_model=True):
    now = time.time()
    exec_time = random.randint(10, 2000)

    description = get_random_phrase(3, 8)
    start_time = datetime.datetime.fromtimestamp(now - exec_time)
    end_time = datetime.datetime.fromtimestamp(now)
    tags = {random.choice(WORDS).upper() for _ in range(random.randint(1, 15))}
    results = [get_random_result_section(False) for _ in range(random.randint(0, 5))]
    files = [get_random_file(False) for _ in range(random.randint(1, 3))]

    max_score = 0
    for result_dict in results:
        result = FakeResultSection(result_dict)
        if result.score > max_score:
            max_score = result.score

    metadata = {random.choice(WORDS).lower(): random.choice(WORDS) for _ in range(random.randint(0, 5))}

    out = {
        "description": description,
        "start_time": start_time,
        "end_time": end_time,
        "tags": tags,
        "results": results,
        "files": files,
        "max_score": max_score,
        "metadata": metadata
    }

    if as_model:
        return FakeSubmission(out)
    return out


def get_random_phrase(wmin=2, wmax=6):
    return " ".join([random.choice(WORDS) for _ in range(random.randint(wmin, wmax))])


def get_random_filename(smin=1, smax=3):
    return "_".join([random.choice(WORDS).lower() for _ in range(random.randint(smin, smax))]) + random.choice(EXT)


def get_random_string(smin=4, smax=24):
    return "".join([random.choice(ALPHA) for _ in range(random.randint(smin, smax))])


if __name__ == "__main__":
    for x in range(10):
        print(get_random_submission())
        break
        print(get_random_file())
        #print(get_random_filename())
        #print(get_random_result_section())
