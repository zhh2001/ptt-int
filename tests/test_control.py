import subprocess
import unittest
from unittest.mock import patch
from control.configure_switch import forwarding_commands, configure_switch_id, run_cli
from control.configure_queues import configure_queues


class ControlTests(unittest.TestCase):
    def test_forwarding_validates_before_sending(self):
        self.assertEqual(forwarding_commands([{"dst_ip":"10.0.0.2/24", "port":510}]),
                         ["table_add PttIngress.ipv4_lpm PttIngress.forward 10.0.0.0/24 => 510"])
        for route in ({"dst_ip":"::/0", "port":1}, {"dst_ip":"0.0.0.0/0", "port":511},
                      {"dst_ip":"10.0.0.2\nreset_state", "port":1}):
            with self.assertRaises(ValueError):
                forwarding_commands([route])

    def test_cli_errors_with_zero_exit_status_are_failures(self):
        for output in ("RuntimeCmd: Error: bad register", "Invalid table name", "Exception"):
            with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                with self.assertRaises(RuntimeError):
                    run_cli(9090, ["x"])

    def test_cli_does_not_use_stale_local_json(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run:
            configure_switch_id(9090, 4095)
            self.assertNotIn("--json", run.call_args.args[0])
            self.assertIn("4095", run.call_args.kwargs["input"])

    def test_queue_command_order_and_all_ports(self):
        with patch("control.configure_queues.run_cli") as cli:
            configure_queues(9090, 128, 100, [1, 2])
            self.assertEqual(cli.call_args.args[1], [
                "set_queue_depth 128 1", "set_queue_rate 100 1",
                "set_queue_depth 128 2", "set_queue_rate 100 2"])
            configure_queues(9090, 128, 0)
            self.assertEqual(cli.call_args.args[1], ["set_queue_depth 128", "set_queue_rate 0"])
            with self.assertRaises(ValueError):
                configure_queues(9090, -1)
