"""Private, single-consumer provisioning queue for the Gunicorn launcher."""
import json
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


_MAX_MESSAGE = 1024 * 1024
_POLL_INTERVAL = 0.05


class ProvisioningBusy(Exception):
    pass


def _publish(path, contents):
    staged = path.with_name(f'.{path.name}')
    staged.write_bytes(contents)
    staged.replace(path)


class ProvisioningClient:
    def __init__(self, directory, *, slots, timeout):
        self.directory = directory
        self.slots = threading.BoundedSemaphore(slots)
        self.timeout = timeout

    def submit(self, token, data, url_root):
        if not self.slots.acquire(blocking=False):
            raise ProvisioningBusy()
        try:
            deadline = time.monotonic() + self.timeout
            job = json.dumps({
                'token': token, 'data': data, 'url_root': url_root, 'deadline': deadline,
            }).encode()
            if len(job) > _MAX_MESSAGE:
                return 413, {'error': 'provisioning_request_too_large'}

            prefix = f'job-{time.monotonic_ns():020d}-'
            with TemporaryDirectory(prefix=prefix, dir=self.directory) as workspace:
                workspace = Path(workspace)
                _publish(workspace / 'request.json', job)
                response = workspace / 'response.json'
                while True:
                    try:
                        status, payload = json.loads(response.read_bytes())
                        return status, payload
                    except FileNotFoundError:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ProvisioningBusy()
                        time.sleep(min(_POLL_INTERVAL, remaining))
        except (OSError, ValueError) as exc:
            raise ProvisioningBusy() from exc
        finally:
            self.slots.release()


def _run_job(request, provision, logger):
    claimed = request.with_name('claimed.json')
    try:
        request.replace(claimed)
        job = json.loads(claimed.read_bytes())
    except FileNotFoundError:
        return  # The web request expired before any changes were made.

    try:
        if time.monotonic() >= job['deadline']:
            return
        result = provision(job['token'], job['data'], job['url_root'])
    except Exception:
        logger.exception('IRSPEEDY provisioning failed')
        result = (500, {'error': 'subscription_create_failed'})

    try:
        _publish(request.with_name('response.json'), json.dumps(result).encode())
    except FileNotFoundError:
        pass  # The caller can safely replay with the same idempotency key.


def serve_provisioning(directory, provision, logger):
    stopping = False
    directory = Path(directory)

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        requests = sorted(directory.glob('job-*/request.json'))
        if not requests:
            time.sleep(_POLL_INTERVAL)
            continue
        for request in requests:
            if stopping:
                break
            try:
                _run_job(request, provision, logger)
            except (OSError, ValueError):
                logger.exception('Could not process an IRSPEEDY queue entry')


@contextmanager
def provisioning_process(command, logger, *, grace_period):
    with TemporaryDirectory(prefix='wgpanel-provision-') as directory:
        stop = threading.Event()

        def launch():
            return subprocess.Popen([*command, directory])

        process = launch()

        def supervise():
            nonlocal process
            while not stop.wait(2):
                if process.poll() is not None:
                    logger.warning('IRSPEEDY provisioning process exited, restarting')
                    try:
                        process = launch()
                    except OSError:
                        logger.exception('Could not restart IRSPEEDY provisioning')

        supervisor = threading.Thread(target=supervise, name='irspeedy-provision', daemon=True)
        supervisor.start()
        try:
            yield directory
        finally:
            stop.set()
            supervisor.join()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=grace_period)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
