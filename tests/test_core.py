"""Unit tests for the pure logic: config parsing, address allocation, validation.

Run:  python -m pytest -q      (or: python -m unittest discover -s tests)
"""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from amnezia_manager import wireguard as wg
from amnezia_manager.errors import NoAddressAvailableError, ValidationError
from amnezia_manager.validators import (
    format_bytes,
    is_expired,
    parse_expiration,
    parse_traffic_limit,
    validate_username,
)

SERVER_CONF = """\
[Interface]
Address = 10.8.1.1/24
ListenPort = 51820
PrivateKey = aGVsbG8td29ybGQtdGhpcy1pcy1ub3QtYS1yZWFsLWtleQ==
Jc = 4
Jmin = 40
Jmax = 70
S1 = 66
S2 = 0
H1 = 1256714129
H2 = 1774876419
H3 = 1521283344
H4 = 2043303484

# alice
[Peer]
PublicKey = QUJDMTIzYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo9PQ==
PresharedKey = cHNrLWtleS1nb2VzLWhlcmUtbm90LXJlYWwtYXQtYWxsPT0=
AllowedIPs = 10.8.1.2/32
"""


class WireguardParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = wg.parse_config(SERVER_CONF)

    def test_interface_fields(self) -> None:
        self.assertEqual(self.cfg.interface["Address"], "10.8.1.1/24")
        self.assertEqual(self.cfg.interface["ListenPort"], "51820")

    def test_awg_params_preserved_and_ordered(self) -> None:
        params = self.cfg.awg_params()
        self.assertEqual(
            list(params), ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"]
        )
        self.assertEqual(params["H4"], "2043303484")

    def test_peer_parsed(self) -> None:
        self.assertEqual(len(self.cfg.peers), 1)
        self.assertEqual(self.cfg.peers[0].allowed_ips, "10.8.1.2/32")
        self.assertEqual(self.cfg.peers[0].comment, "alice")

    def test_interface_raw_has_no_peer(self) -> None:
        self.assertIn("[Interface]", self.cfg.interface_raw)
        self.assertNotIn("[Peer]", self.cfg.interface_raw)

    def test_listen_port(self) -> None:
        self.assertEqual(wg.parse_listen_port(self.cfg.interface), 51820)


class AddressAllocation(unittest.TestCase):
    def setUp(self) -> None:
        self.interface = wg.parse_config(SERVER_CONF).interface

    def test_first_free_skips_server_and_used(self) -> None:
        addr = wg.allocate_address(self.interface, {"10.8.1.2/32", "10.8.1.3"})
        self.assertEqual(addr, "10.8.1.4/32")

    def test_lowest_free_when_gap(self) -> None:
        addr = wg.allocate_address(self.interface, {"10.8.1.3/32"})
        self.assertEqual(addr, "10.8.1.2/32")

    def test_exhaustion_raises(self) -> None:
        used = {f"10.8.1.{i}/32" for i in range(1, 255)}
        with self.assertRaises(NoAddressAvailableError):
            wg.allocate_address(self.interface, used)

    def test_roundtrip_build(self) -> None:
        cfg = wg.parse_config(SERVER_CONF)
        peer = wg.Peer(public_key="k", preshared_key="p", allowed_ips="10.8.1.9/32",
                       comment="bob")
        rebuilt = wg.build_server_config(cfg.interface_raw, [peer])
        self.assertIn("# bob", rebuilt)
        self.assertIn("AllowedIPs = 10.8.1.9/32", rebuilt)
        self.assertIn("Jc = 4", rebuilt)


class ClientConfig(unittest.TestCase):
    def test_contains_awg_params_and_endpoint(self) -> None:
        cfg = wg.parse_config(SERVER_CONF)
        text = wg.build_client_config(
            private_key="priv", address="10.8.1.5/32", dns="1.1.1.1",
            awg_params=cfg.awg_params(), server_public_key="spub",
            preshared_key="psk", endpoint="1.2.3.4:51820",
        )
        self.assertIn("Jmin = 40", text)
        self.assertIn("Endpoint = 1.2.3.4:51820", text)
        self.assertIn("PersistentKeepalive = 25", text)


class Validation(unittest.TestCase):
    def test_valid_usernames(self) -> None:
        for name in ("alice", "bob_1", "team.lead", "a-b-c", "X"):
            self.assertEqual(validate_username(name), name)

    def test_invalid_usernames(self) -> None:
        for name in ("", "_leading", "-nope", "has space", "sym$", "x" * 33):
            with self.assertRaises(ValidationError):
                validate_username(name)

    def test_parse_expiration_forms(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.assertIsNone(parse_expiration("never"))
        self.assertIsNone(parse_expiration(""))
        self.assertEqual(parse_expiration("2026-06-01")[:10], "2026-06-01")
        self.assertTrue(parse_expiration("+30d", now=now).startswith("2026-01-31"))
        self.assertTrue(parse_expiration("+2w", now=now).startswith("2026-01-15"))

    def test_parse_expiration_rejects_garbage(self) -> None:
        with self.assertRaises(ValidationError):
            parse_expiration("tomorrow-ish")

    def test_is_expired(self) -> None:
        past = datetime(2000, 1, 1, tzinfo=timezone.utc).isoformat()
        future = datetime(2100, 1, 1, tzinfo=timezone.utc).isoformat()
        self.assertTrue(is_expired(past))
        self.assertFalse(is_expired(future))
        self.assertFalse(is_expired(None))

    def test_parse_traffic_limit_units(self) -> None:
        self.assertEqual(parse_traffic_limit("1KB"), 1024)
        self.assertEqual(parse_traffic_limit("500MB"), 500 * 1024 ** 2)
        self.assertEqual(parse_traffic_limit("2GB"), 2 * 1024 ** 3)
        self.assertEqual(parse_traffic_limit("1TB"), 1024 ** 4)
        self.assertEqual(parse_traffic_limit("2048"), 2048)

    def test_parse_traffic_limit_unlimited_forms(self) -> None:
        for token in ("unlimited", "none", "never", "", "0", "0GB"):
            self.assertIsNone(parse_traffic_limit(token))

    def test_parse_traffic_limit_rejects_garbage(self) -> None:
        with self.assertRaises(ValidationError):
            parse_traffic_limit("a lot")
        with self.assertRaises(ValidationError):
            parse_traffic_limit("5XB")

    def test_format_bytes(self) -> None:
        self.assertEqual(format_bytes(None), "unlimited")
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1536), "1.50 KB")
        self.assertEqual(format_bytes(1024 ** 3), "1.00 GB")


if __name__ == "__main__":
    unittest.main()
