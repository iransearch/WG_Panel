import base64
from pathlib import Path
from subprocess import PIPE, CalledProcessError, CompletedProcess, TimeoutExpired
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from agent.awg_config import (
    _apply_default_profile, activate_created_interface, new_interface_lines, parameter_lines,
    read_parameters, with_default_profile,
)


class AmneziaWGConfigTests(unittest.TestCase):
    def test_boot_registration_survives_immediate_start_timeout(self):
        def run(command, **kwargs):
            if command[:2] == ["awg-quick", "up"]:
                self.assertNotEqual(kwargs["stdout"], PIPE)
                raise TimeoutExpired(command, kwargs["timeout"])
            return CompletedProcess(command, 0)

        with patch("agent.awg_config.subprocess.run", side_effect=run) as command:
            up_error, boot_error = activate_created_interface(
                "/etc/amnezia/amneziawg/wg11.conf", auto_up=True,
            )
        self.assertIn("timed out", up_error)
        self.assertIsNone(boot_error)
        self.assertEqual(command.call_args_list[0].args[0], [
            "systemctl", "enable", "awg-quick@wg11.service",
        ])

    def test_boot_registration_can_run_without_immediate_start(self):
        with patch("agent.awg_config.subprocess.run") as command:
            command.return_value = CompletedProcess(["systemctl"], 0)
            self.assertEqual(
                activate_created_interface("/etc/amnezia/amneziawg/wg11.conf", auto_up=False),
                (None, None),
            )
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0], ["systemctl", "enable", "awg-quick@wg11.service"])

    def test_boot_failure_is_reported_without_preventing_immediate_start(self):
        with patch("agent.awg_config.subprocess.run") as command:
            command.side_effect = [
                CompletedProcess(["systemctl"], 1, "", "Unit is masked"),
                CompletedProcess(["awg-quick"], 0),
            ]
            self.assertEqual(
                activate_created_interface("/etc/amnezia/amneziawg/wg11.conf", auto_up=True),
                (None, "Unit is masked"),
            )
        self.assertEqual(command.call_args.args[0][:2], ["awg-quick", "up"])

    def test_new_interfaces_share_defaults_but_have_distinct_header_keys(self):
        first = dict(line.split(" = ", 1) for line in new_interface_lines())
        second = dict(line.split(" = ", 1) for line in new_interface_lines())
        self.assertNotEqual(first["HeaderProtectionKey"], second["HeaderProtectionKey"])
        self.assertEqual(len(base64.b64decode(first["HeaderProtectionKey"], validate=True)), 32)
        del first["HeaderProtectionKey"], second["HeaderProtectionKey"]
        self.assertEqual(first, second)
        self.assertEqual(first, {
            "Jc": "6", "Jmin": "48", "Jmax": "135", "S1": "53", "S2": "56",
            "S3": "52", "S4": "13", "H1": "251985833", "H2": "1038694419",
            "H3": "1548780894", "H4": "1701813191", "I1": "<r 164>",
            "ContentPaddingAddition": "21-34", "RekeyAfterTime": "100-134",
            "RekeyTimeout": "4-8", "RejectAfterTime": "165-229", "KeepaliveTimeout": "8-13",
            "MaxHandshakeAttempts": "21-32", "RandomTrailers": "on", "DisableCookies": "on",
        })

    def test_existing_interface_retains_its_keys_hooks_and_peers(self):
        key = base64.b64encode(b"a" * 32).decode("ascii")
        unchanged = "PrivateKey = test\r\nAddress = 10.0.0.1/24\r\nPostUp = hook # preserve\r\n[Peer]\r\nPublicKey = peer\r\n"
        config = f"[Interface]\r\nI2 = <r 16>\r\ns1 = 32\r\nHeaderProtectionKey = {key}\r\n" + unchanged
        updated = with_default_profile(config)
        self.assertTrue(updated.endswith(unchanged))
        self.assertIn(f"HeaderProtectionKey = {key}\r\n", updated)
        self.assertIn("S1 = 53\r\n", updated)
        self.assertNotIn("I2 =", updated)
        self.assertNotIn("s1 = 32", updated)
        self.assertEqual(with_default_profile(updated), updated)

    def test_failed_start_restores_the_previous_config(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "wg0.conf"
            original = b"[Interface]\nAddress = 10.0.0.1/24\nS1 = 32\n"
            path.write_bytes(original)
            start_configs = []

            def run(command, **kwargs):
                if command[:2] == ["systemctl", "start"]:
                    start_configs.append(path.read_bytes())
                    if len(start_configs) == 1:
                        raise CalledProcessError(1, command)
                return CompletedProcess(command, 0)

            with patch("agent.awg_config.subprocess.run", side_effect=run):
                with self.assertRaises(CalledProcessError):
                    _apply_default_profile(path)
            self.assertIn(b"S1 = 53\n", start_configs[0])
            self.assertEqual(start_configs[1], original)
            self.assertEqual(path.read_bytes(), original)

    def test_config_export_only_copies_protocol_fields_from_interface(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "awg0.conf"
            path.write_text(
                "[Interface]\nPrivateKey = server-key\n"
                "h1 = 100-199 # profile\nS3 = 24\nPostUp = hook\n"
                "[Peer]\nH1 = 200-299\nPresharedKey = peer-key\n",
                encoding="utf-8",
            )
            self.assertEqual(parameter_lines(read_parameters(path)), ["S3 = 24", "H1 = 100-199"])

    def test_node_parameters_cannot_add_configuration_lines(self):
        self.assertEqual(
            parameter_lines({"H2": "300-399", "HeaderProtectionKey": "key\nPostUp = hook", "PrivateKey": "secret"}),
            ["H2 = 300-399"],
        )


if __name__ == "__main__":
    unittest.main()
