import queue
import threading
import http.server
import json

import pytest
from assemblyline.common.postprocess import ActionWorker, SubmissionFilter

from assemblyline.odm.models.actions import PostprocessAction, Webhook
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.randomizer import random_minimal_obj


@pytest.fixture
def server():
    hits = queue.Queue()

    class TestServer(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                hits.put(dict(
                    headers=self.headers,
                    body=self.rfile.read(int(self.headers.get('Content-Length', '1')))
                ))
                self.send_response(200, 'data received')
                self.end_headers()
            except Exception as error:
                hits.put(error)

    test_server = http.server.ThreadingHTTPServer(('localhost', 0), TestServer)
    thread = threading.Thread(target=test_server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://localhost:{test_server.server_address[1]}', hits
    finally:
        test_server.shutdown()
        thread.join()


def test_hook(server, config, datastore_connection, redis_connection):
    server_uri, server_hits = server

    action = PostprocessAction(dict(
        enabled=True,
        run_on_completed=True,
        filter="metadata.do_hello: *",
        webhook=Webhook(dict(
            uri=server_uri,
            headers=[dict(name='care-of', value='assemblyline')]
        ))
    ))

    worker = ActionWorker(cache=False, config=config, datastore=datastore_connection, redis_persist=redis_connection)

    worker.actions = {
        'action': (SubmissionFilter(action.filter), action)
    }

    sub: Submission = random_minimal_obj(Submission)
    sub.metadata = dict(ok='bad')
    worker.process_submission(sub, tags=[])

    sub: Submission = random_minimal_obj(Submission)
    sub.metadata = dict(ok='good', do_hello='yes')
    worker.process_submission(sub, tags=[])

    obj = server_hits.get(timeout=3)
    assert obj['headers']['CARE-OF'] == 'assemblyline'
    assert json.loads(obj['body'])['submission']['metadata']['ok'] == 'good'

    assert server_hits.qsize() == 0
