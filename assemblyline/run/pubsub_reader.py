#!/usr/bin/env python

import sys

from assemblyline.remote.datatypes.queues.comms import CommsQueue
from pprint import pprint


if __name__ == "__main__":
    queue_name = None
    if len(sys.argv) > 1:
        queue_name = sys.argv[1]

    if queue_name is None:
        print("\nERROR: You must specify a queue name.\n\npubsub_reader.py [queue_name]")
        exit(1)

    print(f"Listening for messages on '{queue_name}' queue.")

    q = CommsQueue(queue_name)

    try:
        while True:
            for msg in q.listen():
                pprint(msg)
    except KeyboardInterrupt:
        print('Exiting')
    finally:
        q.close()
