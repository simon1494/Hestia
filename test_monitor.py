from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import monitor


def example_container():
    container = MagicMock()
    container.id = "a" * 64
    container.name = "web"
    container.image.id = "sha256:old"
    defaults = {"Env": ["INHERITED=old", "OVERRIDE=original"], "Cmd": ["old"],
                "Healthcheck": {"Test": ["CMD", "old-health"]}, "Labels": {"version": "old"}}
    container.image.attrs = {"Config": defaults}
    container.attrs = {
        "Config": {**deepcopy(defaults), "Image": "example/web:latest", "Hostname": "a" * 12,
                   "Env": ["INHERITED=old", "OVERRIDE=custom", "APP=kept"],
                   "Labels": {"version": "old", "custom": "kept"}},
        "HostConfig": {"NetworkMode": "default", "RestartPolicy": {"Name": "unless-stopped"},
                       "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8081"}]},
                       "Memory": 134217728, "CapDrop": ["NET_RAW"], "ReadonlyRootfs": True},
        "NetworkSettings": {"Networks": {"bridge": {}}},
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "Mounts": [{"Type": "volume", "Name": "persistent-data", "Source": "/var/lib/docker/volumes/data",
                    "Destination": "/data", "RW": True}],
    }
    return container


def example_image():
    image = MagicMock()
    image.id = "sha256:new"
    image.attrs = {"Config": {"Env": ["INHERITED=new", "OVERRIDE=new", "ADDED=yes"],
                              "Cmd": ["new"], "Labels": {"version": "new"},
                              "Healthcheck": {"Test": ["CMD", "new-health"]}}}
    return image


class ConfigTests(unittest.TestCase):
    def test_preserves_runtime_configuration_and_uses_new_image_defaults(self):
        old = example_container()
        config = monitor.replacement_config(old, example_image(), "txn")
        self.assertEqual(config["HostConfig"]["PortBindings"], old.attrs["HostConfig"]["PortBindings"])
        for key in ("RestartPolicy", "Memory", "CapDrop", "ReadonlyRootfs"):
            self.assertEqual(config["HostConfig"][key], old.attrs["HostConfig"][key])
        self.assertEqual(config["HostConfig"]["Mounts"][0]["Source"], "persistent-data")
        self.assertEqual(set(config["Env"]), {"INHERITED=new", "OVERRIDE=custom", "APP=kept", "ADDED=yes"})
        self.assertNotIn("Cmd", config)
        self.assertNotIn("Healthcheck", config)
        self.assertNotIn("Hostname", config)
        self.assertEqual(config["Labels"]["version"], "new")
        self.assertEqual(config["Labels"]["custom"], "kept")
        self.assertEqual(config["Image"], "sha256:new")

    def test_healthcheck_disabled_or_missing_rejected(self):
        for health in ({}, {"Test": ["NONE"]}):
            image = example_image()
            image.attrs["Config"]["Healthcheck"] = health
            with self.assertRaises(monitor.UpdateError):
                monitor.replacement_config(example_container(), image, "txn")

    def test_complex_configuration_rejected_before_mutation(self):
        for host_change in ({"AutoRemove": True}, {"NetworkMode": "custom"}, {"PidMode": "container:x"}):
            old = example_container()
            old.attrs["HostConfig"].update(host_change)
            with self.assertRaises(monitor.UpdateError):
                monitor.replacement_config(old, example_image(), "txn")
            old.stop.assert_not_called()

    def test_explicit_health_and_command_preserved(self):
        old = example_container()
        old.attrs["Config"]["Cmd"] = ["custom-command"]
        old.attrs["Config"]["Healthcheck"] = {"Test": ["CMD", "custom-check"]}
        config = monitor.replacement_config(old, example_image(), "txn")
        self.assertEqual(config["Cmd"], ["custom-command"])
        self.assertEqual(config["Healthcheck"]["Test"], ["CMD", "custom-check"])


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = monitor.State(self.directory.name)
        self.client = MagicMock()
        self.old = example_container()
        self.image = example_image()
        self.config = {"containers": [{"name": "web"}], "health_timeout": 2, "stop_timeout": 1}
        self.client.containers.get.return_value = self.old
        self.client.images.pull.return_value = self.image

    def test_pull_failure_leaves_current_container_alone(self):
        self.client.images.pull.side_effect = RuntimeError("unauthorized")
        with self.assertLogs("hestia", level="ERROR"):
            self.assertFalse(monitor.check_once(self.client, self.config, self.state))
        self.old.stop.assert_not_called()
        self.client.api.create_container_from_config.assert_not_called()

    def test_only_configured_container_and_config_image_are_used(self):
        self.client.images.pull.return_value.id = self.old.image.id
        self.assertTrue(monitor.check_once(self.client, self.config, self.state))
        self.client.containers.get.assert_called_once_with("web")
        self.client.containers.list.assert_not_called()
        self.client.images.pull.assert_called_once_with("example/web:latest")

    def test_explicit_tracking_image_and_dry_run(self):
        self.config["containers"][0]["image"] = "ghcr.io/owner/web:latest"
        self.assertTrue(monitor.check_once(self.client, self.config, self.state, dry_run=True))
        self.client.images.pull.assert_called_once_with("ghcr.io/owner/web:latest")
        self.old.stop.assert_not_called()
        self.client.api.create_container_from_config.assert_not_called()

    def test_failed_digest_persists_and_is_not_retried(self):
        self.state.data["failed_images"]["web"] = self.image.id
        self.state.save()
        restored = monitor.State(self.directory.name)
        with self.assertLogs("hestia", level="WARNING"):
            self.assertFalse(monitor.check_once(self.client, self.config, restored))
        self.old.stop.assert_not_called()

    def test_missing_health_and_restart_are_failures(self):
        for state in ({"Running": True}, {"Running": False},
                      {"Running": True, "Restarting": True, "Health": {"Status": "healthy"}},
                      {"Running": True, "Health": {"Status": "unhealthy"}}):
            self.old.attrs["State"] = state
            with self.assertRaises(monitor.UpdateError):
                monitor.wait_healthy(self.old, 1)

    def test_starting_health_times_out(self):
        self.old.attrs["State"]["Health"]["Status"] = "starting"
        with self.assertRaisesRegex(monitor.UpdateError, "timed out"):
            monitor.wait_healthy(self.old, 0)

    def test_stopped_container_is_not_started(self):
        self.old.attrs["State"]["Running"] = False
        self.assertTrue(monitor.check_once(self.client, self.config, self.state))
        self.client.images.pull.assert_not_called()
        self.old.start.assert_not_called()

    def test_create_failure_restores_without_removing_original(self):
        self.client.api.create_container_from_config.side_effect = RuntimeError("create failed")
        with self.assertLogs("hestia", level="WARNING"):
            with self.assertRaisesRegex(RuntimeError, "create failed"):
                monitor.replace(self.client, self.old, self.image, self.state, 2, 1)
        self.old.remove.assert_not_called()
        self.old.stop.assert_not_called()
        self.assertIsNone(self.state.data["transaction"])
        self.assertEqual(self.state.data["failed_images"]["web"], self.image.id)

    def test_pending_recovery_failure_cannot_be_overwritten(self):
        self.state.data["transaction"] = {"id": "pending"}
        with patch.object(monitor, "recover", side_effect=monitor.UpdateError("recovery failed")):
            with self.assertRaises(monitor.UpdateError):
                monitor.check_once(self.client, self.config, self.state)
        self.assertEqual(self.state.data["transaction"], {"id": "pending"})
        self.client.images.pull.assert_not_called()

    def test_configuration_requires_explicit_targets(self):
        path = Path(self.directory.name) / "config.json"
        path.write_text(json.dumps({"containers": []}))
        with self.assertRaises(ValueError):
            monitor.load_config(path)


if __name__ == "__main__":
    unittest.main()
