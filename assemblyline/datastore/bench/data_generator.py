
import random

import time

from assemblyline.datastore.bench.model import FakeFileObject, FakeResultSection, FakeSubmission
from hashlib import sha256

from assemblyline.odm.randomizer import get_random_filename, get_random_phrase, get_random_iso_date, get_random_word, \
    get_random_mapping


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
    start_time = get_random_iso_date(now - exec_time)
    end_time = get_random_iso_date(now)
    tags = list({get_random_word().upper() for _ in range(random.randint(1, 15))})
    results = [get_random_result_section(False) for _ in range(random.randint(0, 5))]
    files = [get_random_file(False) for _ in range(random.randint(1, 3))]

    max_score = 0
    for result_dict in results:
        result = FakeResultSection(result_dict)
        if result.score > max_score:
            max_score = result.score

    metadata = get_random_mapping(None)

    out = {
        "description": description,
        "start_time": start_time,
        "end_time": end_time,
        "tags": tags,
        "results": results,
        "files": files,
        "max_score": max_score,
        "metadata": metadata,
        "classification": random.choice(["R//ANY", "U", "U//ADM", "R", "R//SU//REL TO D2"]),
        "submission_type": random.choice(["live", "user", "client"])
    }

    if as_model:
        return FakeSubmission(out)
    return out


if __name__ == "__main__":
    for x in range(10):
        print(get_random_submission())
        print(get_random_submission(as_model=False))
