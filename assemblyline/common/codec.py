import os
import tempfile

from cart import pack_stream, unpack_stream
from io import BytesIO

from assemblyline.common import identify

NEUTERED_FORMAT = [
    'archive/cart'
]


# noinspection PyBroadException
def decode_file(original_path, fileinfo):
    extracted_path = None
    original_name = None
    al_meta = {}
    if fileinfo['type'] in NEUTERED_FORMAT:
        extracted_fd, extracted_path = tempfile.mkstemp()
        extracted_file = os.fdopen(extracted_fd, 'wb')

        original_file = open(original_path)
        cart_extracted = False
        try:
            hdr, _ = unpack_stream(original_file, extracted_file)
            original_name = hdr.get('name', os.path.basename(original_path))
            al_meta = hdr.get("al", {}).get("meta", {})
            cart_extracted = True

        except Exception:
            extracted_path = None
            original_name = None
            al_meta = {}
            fileinfo['type'] = 'corrupted/cart'

        finally:
            extracted_file.close()
            original_file.close()

        if cart_extracted:
            fileinfo = identify.fileinfo(extracted_path)

    return extracted_path, original_name, fileinfo, al_meta


# noinspection PyUnusedLocal
def encode_file(data, file_format, name):
    error = {}
    already_encoded = False

    file_info = identify.ident(data, len(data))

    if file_info['type'] in NEUTERED_FORMAT:
        already_encoded = True
    elif file_format == 'cart':
        ostream = BytesIO()
        pack_stream(BytesIO(data), ostream, {"name": name})
        data = ostream.getvalue()
    elif file_format != 'raw':
        error['code'] = 500
        error['text'] = "Invalid file format specified."

    return data, error, already_encoded
