#!/usr/bin/env python3
"""Read-only native network reports, including real bound TCP/UDP sockets."""
import json
import socket
import subprocess
import sys
import unittest
from pathlib import Path

BINARY = str(Path(sys.argv.pop(1)).resolve())


class Network(unittest.TestCase):
    def cm(self, *args, expected=0):
        r = subprocess.run([BINARY, "net", *args, "--json"], text=True, capture_output=True, timeout=15)
        self.assertEqual(r.returncode, expected, (args, r.stdout, r.stderr))
        return json.loads(r.stdout) if expected == 0 else r

    def test_interfaces_addresses_routes(self):
        interfaces = self.cm("interfaces")
        self.assertIn("lo", [i["name"] for i in interfaces])
        for interface in interfaces:
            self.assertGreaterEqual(interface["mtu"], 0)
            self.assertGreaterEqual(interface["rx_bytes"], 0)
        self.assertIsInstance(self.cm("addresses"), list)
        self.assertIsInstance(self.cm("routes"), list)
        self.assertTrue(self.cm("route", "get", "127.0.0.1"))
        self.cm("route", "get", "localhost", expected=1)
        self.cm("route", "get", "127.0.0.1;drop", expected=1)

    def test_dns_labels_its_source_and_interpretation(self):
        dns = self.cm("dns")
        self.assertIn(dns["source"], ("systemd-resolved", "/etc/resolv.conf"))
        self.assertIn("interpretation", dns)
        self.assertIsInstance(dns["servers"], list)

    def test_bound_listeners(self):
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen()
            udp.bind(("127.0.0.1", 0))
            listeners = self.cm("listeners")
            for protocol, port in [("tcp", tcp.getsockname()[1]), ("udp", udp.getsockname()[1])]:
                self.assertTrue(any(x["protocol"] == protocol and x["port"] == port
                                    for x in listeners), listeners)

    def test_public_ip_requires_explicit_https_and_valid_options(self):
        for options in [("--url", "http://example.test"), ("--url", "file:///etc/shadow"),
                        ("--family", "5"), ("--url", "https://example.test/\ninjected")]:
            self.cm("public-ip", *options, expected=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
