"""Opt-in integration tests using isolated resources and an existing base image.

HESTIA_DOCKER_TESTS=1 python -m unittest test_docker_integration -v
The base defaults to zeta-ka:local; no registry credentials are needed.
"""

from copy import deepcopy
import io
import os
import socket
import tempfile
import unittest
from unittest.mock import patch
import uuid

import docker

import monitor


@unittest.skipUnless(os.environ.get("HESTIA_DOCKER_TESTS") == "1", "Docker integration tests are opt-in")
class DockerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = docker.from_env(timeout=120)
        cls.addClassCleanup(cls.client.close)
        cls.prefix = "hestia-test-" + uuid.uuid4().hex[:12]
        cls.images = {}
        base = os.environ.get("HESTIA_TEST_IMAGE", "zeta-ka:local")
        cls.client.images.get(base)  # Require the local fixture; never pull a base image.
        for revision in ("old", "new", "broken"):
            health = "exit 1" if revision == "broken" else "wget -q -O /dev/null http://127.0.0.1:8080/healthz"
            dockerfile = (f"FROM {base}\nLABEL test.revision={revision}\n"
                          f"ENV TEST_DEFAULT={revision}\n"
                          "HEALTHCHECK --interval=1s --timeout=1s --start-period=1s --retries=1 "
                          f"CMD {health}\n")
            image, _ = cls.client.images.build(fileobj=io.BytesIO(dockerfile.encode()),
                                               tag=f"{cls.prefix}:{revision}", rm=True, pull=False)
            cls.images[revision] = image
            cls.addClassCleanup(cls.client.images.remove, image.id)

    def setUp(self):
        self.name = f"{self.prefix}-{uuid.uuid4().hex[:8]}"
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = monitor.State(self.directory.name)
        self.volume = self.client.volumes.create(name=self.name + "-data")
        self.addCleanup(self.volume.remove)
        self.addCleanup(self.clean_containers)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.old = self.client.containers.run(
            self.images["old"].id, name=self.name, detach=True,
            ports={"8080/tcp": ("127.0.0.1", self.port)},
            restart_policy={"Name": "unless-stopped"},
            environment={"CUSTOM_ENV": "preserved"},
            labels={"io.hestia.test": self.name},
            volumes={self.volume.name: {"bind": "/data", "mode": "rw"}},
            mem_limit="128m", cap_drop=["NET_RAW"],
        )
        monitor.wait_healthy(self.old, 30)
        result = self.old.exec_run(["sh", "-c", "printf persistent > /data/check"], user="0")
        self.assertEqual(result.exit_code, 0)

    def clean_containers(self):
        for container in self.client.containers.list(all=True, filters={"label": f"io.hestia.test={self.name}"}):
            container.remove(force=True, v=True)

    def assert_config_and_data(self, container):
        container.reload()
        self.assertEqual(container.attrs["HostConfig"]["PortBindings"]["8080/tcp"],
                         [{"HostIp": "127.0.0.1", "HostPort": str(self.port)}])
        self.assertEqual(container.attrs["HostConfig"]["RestartPolicy"]["Name"], "unless-stopped")
        self.assertEqual(container.attrs["HostConfig"]["Memory"], 128 * 1024 * 1024)
        self.assertIn("NET_RAW", container.attrs["HostConfig"]["CapDrop"])
        self.assertIn("CUSTOM_ENV=preserved", container.attrs["Config"]["Env"])
        self.assertEqual(container.exec_run(["cat", "/data/check"]).output, b"persistent")
        self.assertEqual(container.attrs["State"]["Health"]["Status"], "healthy")

    def test_successful_update_preserves_config_and_data(self):
        monitor.replace(self.client, self.old, self.images["new"], self.state, 30, 5)
        current = self.client.containers.get(self.name)
        self.assertEqual(current.image.id, self.images["new"].id)
        self.assert_config_and_data(current)
        self.assertIn("TEST_DEFAULT=new", current.attrs["Config"]["Env"])
        self.assertIsNone(monitor.get_optional(self.client, self.old.id))
        self.assertIsNone(self.state.data["transaction"])
        self.client.images.get(self.images["old"].id)  # The old image was not deleted.

    def test_unhealthy_update_restores_original_container(self):
        with self.assertLogs("hestia", level="WARNING"):
            with self.assertRaises(monitor.UpdateError):
                monitor.replace(self.client, self.old, self.images["broken"], self.state, 30, 5)
        current = self.client.containers.get(self.name)
        self.assertEqual(current.id, self.old.id)
        self.assert_config_and_data(current)
        self.assertEqual(self.state.data["failed_images"][self.name], self.images["broken"].id)
        self.assertIsNone(self.state.data["transaction"])

    def test_start_failure_restores_original_container(self):
        real_start = docker.models.containers.Container.start
        def failing_start(container, **kwargs):
            if container.id != self.old.id:
                raise RuntimeError("Injected candidate start failure")
            return real_start(container, **kwargs)
        with patch.object(docker.models.containers.Container, "start", failing_start):
            with self.assertLogs("hestia", level="WARNING"):
                with self.assertRaisesRegex(RuntimeError, "Injected"):
                    monitor.replace(self.client, self.old, self.images["new"], self.state, 30, 5)
        current = self.client.containers.get(self.name)
        self.assertEqual(current.id, self.old.id)
        self.assert_config_and_data(current)

    def test_recovers_interrupted_update_after_process_restart(self):
        original_save = self.state.save
        def simulate_crash():
            original_save()
            transaction = self.state.data["transaction"]
            if transaction and transaction.get("candidate_id"):
                raise SystemExit("Injected process interruption")
        with patch.object(self.state, "save", simulate_crash):
            with self.assertRaises(SystemExit):
                monitor.replace(self.client, self.old, self.images["new"], self.state, 30, 5)
        # Simulate interruption after the original has stopped and been renamed.
        self.old.update(restart_policy={"Name": "no"})
        self.old.stop(timeout=5)
        self.old.rename(self.name + "-interrupted")
        restarted_state = monitor.State(self.directory.name)
        with self.assertLogs("hestia", level="WARNING"):
            monitor.recover(self.client, restarted_state, 30, 5)
        current = self.client.containers.get(self.name)
        self.assertEqual(current.id, self.old.id)
        self.assert_config_and_data(current)
        self.assertIsNone(restarted_state.data["transaction"])


if __name__ == "__main__":
    unittest.main()
