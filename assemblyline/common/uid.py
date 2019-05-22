
import baseconv
import uuid


def get_random_id():
    return baseconv.base62.encode(uuid.uuid4().int)