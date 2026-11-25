import logging
import os
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

from panel_core.irspeedy_queue import ProvisioningBusy, ProvisioningClient, provisioning_process


_WORKER = """
import logging
import os
import sys
import time
from pathlib import Path
from panel_core.irspeedy_queue import serve_provisioning

markers = Path(sys.argv[1])

def provision(token, data, url_root):
    (markers / token).touch()
    if data.get("pause"):
        while not (markers / "release").exists():
            time.sleep(0.01)
    return 201, {"pid": os.getpid(), "url_root": url_root, "token": token}

serve_provisioning(sys.argv[2], provision, logging.getLogger())
"""


def _wait_for(path):
    deadline = time.monotonic() + 5
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f'Timed out waiting for {path.name}')
        time.sleep(0.01)


class ProvisioningQueueTests(unittest.TestCase):
    def test_shared_serial_process_and_reserved_web_capacity(self):
        with TemporaryDirectory() as directory:
            markers = Path(directory)
            command = [sys.executable, "-c", _WORKER, directory]
            with provisioning_process(command, logging.getLogger(), grace_period=2) as queue_directory:
                url = "https://panel.example.test:8443/panel/"
                first_client = ProvisioningClient(queue_directory, slots=1, timeout=5)
                second_client = ProvisioningClient(queue_directory, slots=1, timeout=5)
                with ThreadPoolExecutor(max_workers=2) as callers:
                    first = callers.submit(first_client.submit, "first", {"pause": True}, url)
                    try:
                        _wait_for(markers / "first")
                        with self.assertRaises(ProvisioningBusy):
                            first_client.submit("overflow", {}, url)
                        second = callers.submit(second_client.submit, "second", {}, url)
                        with self.assertRaises(TimeoutError):
                            second.result(timeout=0.05)
                        self.assertFalse((markers / "second").exists())
                    finally:
                        (markers / "release").touch()
                    status, first_payload = first.result(timeout=5)
                    self.assertEqual(status, 201)
                    self.assertNotEqual(first_payload["pid"], os.getpid())
                    self.assertEqual(first_payload["url_root"], url)
                    self.assertEqual(second.result(timeout=5), (
                        201, {**first_payload, "token": "second"},
                    ))

    def test_timed_out_job_waiting_in_queue_does_not_run(self):
        with TemporaryDirectory() as directory:
            markers = Path(directory)
            command = [sys.executable, "-c", _WORKER, directory]
            with provisioning_process(command, logging.getLogger(), grace_period=2) as queue_directory:
                url = "https://panel.example.test/"
                client = ProvisioningClient(queue_directory, slots=2, timeout=5)
                short = ProvisioningClient(queue_directory, slots=1, timeout=0.1)
                with ThreadPoolExecutor(max_workers=1) as callers:
                    first = callers.submit(client.submit, "first", {"pause": True}, url)
                    try:
                        _wait_for(markers / "first")
                        with self.assertRaises(ProvisioningBusy):
                            short.submit("expired", {}, url)
                    finally:
                        (markers / "release").touch()
                    self.assertEqual(first.result(timeout=5)[0], 201)
                    self.assertEqual(client.submit("next", {}, url)[0], 201)
                    self.assertFalse((markers / "expired").exists())
