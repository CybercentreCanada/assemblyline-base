import base64
import bcrypt
import hashlib
import hmac
import os
import re
import struct
import time
from typing import List, Optional

UPPERCASE = r'[A-Z]'
LOWERCASE = r'[a-z]'
NUMBER = r'[0-9]'
SPECIAL = r'[ !#$@%&\'()*+,-./[\\\]^_`{|}~"]'
PASS_BASIC = [chr(x + 65) for x in range(26)] + \
             [chr(x + 97) for x in range(26)] + \
             [str(x) for x in range(10)] + \
             ["!", "@", "$", "^", "?", "&", "*", "(", ")"]


def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h


def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time())//30)


def generate_random_secret():
    return base64.b32encode(os.urandom(25)).decode("UTF-8")


def get_password_hash(password) -> str:
    if password is None or len(password) == 0:
        return None

    if isinstance(password, str):
        password = password.encode()

    return bcrypt.hashpw(password, bcrypt.gensalt()).decode()


def verify_password(password, pw_hash):
    if isinstance(password, str):
        password = password.encode()

    if isinstance(pw_hash, str):
        pw_hash = pw_hash.encode()

    try:
        return bcrypt.checkpw(password, pw_hash)
    except ValueError:
        return False
    except TypeError:
        return False


def get_password_requirement_message(lower: bool = True, upper: bool = True, number: bool = False,
                                     special: bool = False, min_length: int = 12) -> str:
    msg = f"Password needs to be at least {min_length} characters"

    if lower or upper or number or special:
        msg += " with the following characteristics: "
        specs = []
        if lower:
            specs.append("lowercase letters")
        if upper:
            specs.append("uppercase letters")
        if number:
            specs.append("numbers")
        if special:
            specs.append("special characters")

        msg += ", ".join(specs)

    return msg


def check_password_requirements(password: str, lower: bool = True, upper: bool = True, number: bool = False,
                                special: bool = False, min_length: int = 12) -> bool:
    check_upper = re.compile(UPPERCASE)
    check_lower = re.compile(LOWERCASE)
    check_number = re.compile(NUMBER)
    check_special = re.compile(SPECIAL)

    if get_password_hash(password) is None:
        return True

    if len(password) < min_length:
        return False

    if upper and len(check_upper.findall(password)) == 0:
        return False

    if lower and len(check_lower.findall(password)) == 0:
        return False

    if number and len(check_number.findall(password)) == 0:
        return False

    if special and len(check_special.findall(password)) == 0:
        return False

    return True


def get_random_password(alphabet: Optional[List] = None, length: int = 24) -> str:
    if alphabet is None:
        alphabet = PASS_BASIC
    r_bytes = bytearray(os.urandom(length))
    a_list = []

    for byte in r_bytes:
        while byte >= (256 - (256 % len(alphabet))):
            byte = ord(os.urandom(1))
        a_list.append(alphabet[byte % len(alphabet)])

    return "".join(a_list)
