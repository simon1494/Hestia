"""Update explicitly selected Docker containers, with health checks and recovery."""

import argparse
from contextlib import closing, contextmanager
from copy import deepcopy
import json
import logging
import os
from pathlib import Path
import signal
import threading
import time
import uuid

import docker
from docker.errors import NotFound


LOG = logging.getLogger("hestia")
TRANSACTION_LABEL = "io.hestia.transaction"


class UpdateError(RuntimeError):
    pass


def load_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    targets = config.get("containers", [])
    if not targets or not isinstance(targets, list):
        raise ValueError("Configure at least one container in 'containers'.")
    names = set()
    for target in targets:
        name = target.get("name")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("Each container needs a unique, nonempty name.")
        if "image" in target and (not isinstance(target["image"], str) or not target["image"]):
            raise ValueError("The optional image reference must be a nonempty string.")
        names.add(name)
    for key, default in (("interval", 60), ("health_timeout", 120), ("stop_timeout", 20)):
        config.setdefault(key, default)
        if not isinstance(config[key], (int, float)) or config[key] <= 0:
            raise ValueError(f"{key} must be positive.")
    return config


class State:
    """Durable journal; no container environment or registry secrets are stored."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / "state.json"
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {
            "transaction": None, "failed_images": {}
        }

    def save(self):
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(self.data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)
        if os.name != "nt":
            descriptor = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


@contextmanager
def single_instance(directory):
    """OS lock is released even when the monitor crashes."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "monitor.lock").open("a+b") as stream:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            if not stream.read(1):
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def has_healthcheck(config):
    test = (config.get("Healthcheck") or {}).get("Test") or []
    return bool(test) and test[0] != "NONE"


def wait_healthy(container, timeout):
    deadline = time.monotonic() + timeout
    while True:
        container.reload()
        state = container.attrs["State"]
        if not state.get("Running") or state.get("Restarting"):
            raise UpdateError(f"{container.name} stopped or restarted during validation.")
        health = state.get("Health", {}).get("Status")
        if health == "healthy":
            return
        if health == "unhealthy" or not health:
            raise UpdateError(f"{container.name}: health status {health or 'missing'}.")
        if time.monotonic() >= deadline:
            raise UpdateError(f"{container.name}: health check timed out.")
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def replacement_config(container, image, transaction_id):
    """Use Docker's native config to retain ports, limits and security options."""
    attrs = container.attrs
    config = deepcopy(attrs["Config"])
    host = deepcopy(attrs["HostConfig"])
    labels = config.get("Labels") or {}
    if labels.get("com.docker.compose.config-hash") or labels.get("com.docker.swarm.service.id"):
        raise UpdateError("Compose/Swarm containers must be updated by their orchestrator.")
    if host.get("AutoRemove"):
        raise UpdateError("AutoRemove containers cannot be rolled back.")
    if host.get("NetworkMode") not in ("default", "bridge", "host", "none"):
        raise UpdateError("Custom/shared networks are not supported; no changes made.")
    if any(net not in ("bridge", "host", "none") for net in attrs["NetworkSettings"]["Networks"]):
        raise UpdateError("Additional networks are not supported; no changes made.")
    if host.get("Links") or host.get("VolumesFrom") or any(
        str(host.get(key, "")).startswith("container:") for key in ("PidMode", "IpcMode")
    ):
        raise UpdateError("Shared container dependencies cannot be recreated safely.")

    previous = container.image.attrs["Config"]
    incoming = image.attrs["Config"]
    # Inherited defaults should follow the new image, explicit overrides remain.
    for key in ("Cmd", "Entrypoint", "User", "WorkingDir", "Healthcheck", "StopSignal", "Shell"):
        if config.get(key) == previous.get(key):
            config.pop(key, None)
    def env_dict(items):
        return dict(item.split("=", 1) for item in items or [] if "=" in item)
    previous_env = env_dict(previous.get("Env"))
    environment = env_dict(incoming.get("Env"))
    environment.update({key: value for key, value in env_dict(config.get("Env")).items()
                        if previous_env.get(key) != value})
    config["Env"] = [f"{key}={value}" for key, value in environment.items()]
    new_labels = dict(incoming.get("Labels") or {})
    new_labels.update({key: value for key, value in labels.items()
                       if (previous.get("Labels") or {}).get(key) != value})
    new_labels[TRANSACTION_LABEL] = transaction_id
    config["Labels"] = new_labels
    if config.get("Hostname") == container.id[:12]:
        config.pop("Hostname")

    # Reuse anonymous and named volumes, preserving explicit --mount options.
    explicit_mounts = {mount["Target"]: mount for mount in host.get("Mounts") or []}
    mounts = []
    for mount in attrs.get("Mounts", []):
        target = mount["Destination"]
        if mount["Type"] == "tmpfs":
            if target in explicit_mounts:
                mounts.append(explicit_mounts[target])
            continue  # --tmpfs lives in HostConfig.Tmpfs
        if target in explicit_mounts:
            mounts.append(explicit_mounts[target])
        elif mount["Type"] in ("bind", "volume"):
            item = {"Type": mount["Type"], "Target": target,
                    "Source": mount.get("Name") if mount["Type"] == "volume" else mount["Source"],
                    "ReadOnly": not mount["RW"]}
            if mount["Type"] == "bind" and mount.get("Propagation"):
                item["BindOptions"] = {"Propagation": mount["Propagation"]}
            mounts.append(item)
        else:
            raise UpdateError(f"Unsupported mount type: {mount['Type']}")
    host.pop("Binds", None)
    host["Mounts"] = mounts
    config["HostConfig"] = host
    config["Image"] = image.id  # Pin this transaction to the image actually pulled.
    effective = dict(incoming)
    effective.update(config)
    if not has_healthcheck(effective):
        raise UpdateError("A Docker HEALTHCHECK is required before automatic updates.")
    return config


def get_optional(client, identifier):
    try:
        return client.containers.get(identifier)
    except NotFound:
        return None


def candidate_for(client, transaction):
    candidate = get_optional(client, transaction.get("candidate_id") or transaction["candidate_name"])
    # After a crash between rename and journal write, also look at the final name.
    if candidate is None:
        candidate = get_optional(client, transaction["name"])
    if candidate and candidate.attrs["Config"].get("Labels", {}).get(TRANSACTION_LABEL) == transaction["id"]:
        return candidate
    return None


def recover(client, state, health_timeout, stop_timeout):
    transaction = state.data["transaction"]
    if not transaction:
        return
    old = get_optional(client, transaction["old_id"])
    candidate = candidate_for(client, transaction)
    if transaction["phase"] == "committed":
        # Commit was written only after health validation. Cleanup is retryable.
        if old:
            old.remove()  # Keep its image and volumes for manual recovery.
        state.data["transaction"] = None
        state.save()
        return
    if old is None:
        raise UpdateError("Original container is missing; transaction retained for manual recovery.")
    if candidate:
        candidate.stop(timeout=stop_timeout)
        candidate.remove()
    old.reload()
    if old.name != transaction["name"]:
        old.rename(transaction["name"])
    old.update(restart_policy=transaction["restart_policy"])
    old.reload()
    if not old.attrs["State"]["Running"]:
        old.start()
    wait_healthy(old, health_timeout)
    state.data["failed_images"][transaction["name"]] = transaction["image_id"]
    state.data["transaction"] = None
    state.save()
    LOG.warning("%s: previous container restored and healthy.", transaction["name"])


def replace(client, old, image, state, health_timeout, stop_timeout):
    old.reload()
    if not old.attrs["State"].get("Running"):
        raise UpdateError("Container was stopped; update cancelled.")
    if old.attrs["State"].get("Health", {}).get("Status") != "healthy":
        raise UpdateError("The current container must be healthy before an update.")
    transaction_id = uuid.uuid4().hex
    config = replacement_config(old, image, transaction_id)
    name = old.name
    transaction = {
        "id": transaction_id, "name": name, "old_id": old.id,
        "image_id": image.id, "candidate_name": f"{name}-hestia-{transaction_id[:12]}",
        "restart_policy": deepcopy(old.attrs["HostConfig"]["RestartPolicy"]),
        "phase": "prepared",
    }
    state.data["transaction"] = transaction
    state.save()
    try:
        created = client.api.create_container_from_config(config, name=transaction["candidate_name"])
        transaction["candidate_id"] = created["Id"]
        state.save()
        candidate = client.containers.get(created["Id"])
        # Prevent the backup competing for ports if Docker restarts mid-update.
        old.update(restart_policy={"Name": "no"})
        old.stop(timeout=stop_timeout)
        old.rename(f"{name}-hestia-backup-{transaction_id[:12]}")
        candidate.rename(name)
        candidate.start()
        wait_healthy(candidate, health_timeout)
        transaction["phase"] = "committed"
        state.data["failed_images"].pop(name, None)
        try:
            state.save()
        except Exception:
            transaction["phase"] = "prepared"
            raise
    except Exception:
        LOG.exception("%s: update failed; recovering previous container.", name)
        recover(client, state, health_timeout, stop_timeout)
        raise
    recover(client, state, health_timeout, stop_timeout)
    LOG.info("%s: updated and healthy (%s).", name, image.short_id)


def check_once(client, config, state, dry_run=False, retry_failed=False):
    if state.data["transaction"]:
        if dry_run:
            raise UpdateError("Pending recovery exists; run without --dry-run to recover first.")
        recover(client, state, config["health_timeout"], config["stop_timeout"])
    success = True
    for target in config["containers"]:
        if state.data["transaction"]:
            break  # Never overwrite a journal whose recovery failed.
        name = target["name"]
        try:
            container = client.containers.get(name)
            if not container.attrs["State"].get("Running"):
                LOG.info("%s: stopped; left untouched.", name)
                continue
            reference = target.get("image") or container.attrs["Config"]["Image"]
            LOG.info("%s: checking %s.", name, reference)
            # Uses the service user's Docker credentials (including GHCR).
            latest = client.images.pull(reference)
            if latest.id == container.image.id:
                LOG.info("%s: already up to date.", name)
                continue
            if state.data["failed_images"].get(name) == latest.id and not retry_failed:
                LOG.warning("%s: this image failed previously; waiting for another image.", name)
                success = False
                continue
            replacement_config(container, latest, "preflight")
            if dry_run:
                LOG.info("%s: update available; dry run, container unchanged.", name)
                continue
            replace(client, container, latest, state, config["health_timeout"], config["stop_timeout"])
        except Exception:
            LOG.exception("%s: check/update failed.", name)
            success = False
    return success


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="hestia.json")
    parser.add_argument("--state-dir", default=".hestia")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Pull and validate without replacing containers.")
    parser.add_argument("--retry-failed", action="store_true", help="Retry a rejected image (requires --once).")
    args = parser.parse_args()
    if args.retry_failed and not args.once:
        parser.error("--retry-failed requires --once")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stopped = threading.Event()
    # Finish or roll back the current transaction before exiting on SIGTERM.
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())
    try:
        config = load_config(args.config)
        with single_instance(args.state_dir):
            state = State(args.state_dir)
            with closing(docker.from_env(timeout=120)) as client:
                client.ping()
                while not stopped.is_set():
                    success = check_once(client, config, state, args.dry_run, args.retry_failed)
                    if args.once or args.dry_run:
                        return 0 if success else 1
                    stopped.wait(config["interval"])
        return 0
    except Exception:
        LOG.exception("Hestia could not continue.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
