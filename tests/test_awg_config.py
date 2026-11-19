import base64
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from agent.awg_config import new_interface_lines, parameter_lines, read_parameters


class AmneziaWGConfigTests(unittest.TestCase):
    def test_new_interfaces_have_distinct_header_keys(self):
        first = dict(line.split(" = ", 1) for line in new_interface_lines())
        second = dict(line.split(" = ", 1) for line in new_interface_lines())
        self.assertNotEqual(first["HeaderProtectionKey"], second["HeaderProtectionKey"])
        self.assertEqual(len(base64.b64decode(first["HeaderProtectionKey"], validate=True)), 32)
        self.assertTrue(all(int(first[f"S{i}"]) >= 12 for i in range(1, 5)))

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
