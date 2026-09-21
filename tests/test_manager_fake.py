"""Integration tests for AmneziaManager against the in-memory fake backend."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from amnezia_manager import AmneziaManager
from amnezia_manager.config import Config
from amnezia_manager.errors import UserExistsError, UserNotFoundError
from amnezia_manager import wireguard as wg


class ManagerFakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        cfg = Config(fake_backend=True, db_path=str(Path(self.tmp.name) / "u.db"),
                     log_path=str(Path(self.tmp.name) / "cli.log"))
        self.mgr = AmneziaManager(cfg)

    def tearDown(self) -> None:
        self.mgr.close()
        self.tmp.cleanup()

    def test_create_assigns_sequential_ips(self) -> None:
        a = self.mgr.create_user("alice")
        b = self.mgr.create_user("bob")
        self.assertEqual(a.address, "10.8.1.2/32")
        self.assertEqual(b.address, "10.8.1.3/32")

    def test_duplicate_rejected(self) -> None:
        self.mgr.create_user("alice")
        with self.assertRaises(UserExistsError):
            self.mgr.create_user("alice")

    def test_ip_reused_after_delete(self) -> None:
        self.mgr.create_user("alice")
        self.mgr.create_user("bob")
        self.mgr.delete_user("alice")
        c = self.mgr.create_user("carol")
        self.assertEqual(c.address, "10.8.1.2/32")

    def test_disable_removes_peer_from_container_conf(self) -> None:
        self.mgr.create_user("alice")
        self.mgr.create_user("bob")
        self.mgr.set_enabled("alice", False)
        conf = self.mgr.backend.read_file(self.mgr._conf_path)
        peers = wg.parse_config(conf).peers
        names = {p.comment for p in peers}
        self.assertEqual(names, {"bob"})

    def test_expired_user_not_a_peer(self) -> None:
        self.mgr.create_user("alice", expiration="2000-01-01")
        conf = self.mgr.backend.read_file(self.mgr._conf_path)
        self.assertEqual(wg.parse_config(conf).peers, [])
        # re-enabling the date brings it back
        self.mgr.set_expiration("alice", "+30d")
        conf = self.mgr.backend.read_file(self.mgr._conf_path)
        self.assertEqual(len(wg.parse_config(conf).peers), 1)

    def test_client_config_roundtrips(self) -> None:
        self.mgr.create_user("alice")
        text = self.mgr.client_config("alice")
        parsed = wg.parse_config(text)
        self.assertEqual(parsed.interface["Address"], "10.8.1.2/32")
        self.assertIn("Jc", parsed.interface)
        self.assertEqual(len(parsed.peers), 1)
        self.assertTrue(parsed.peers[0].endpoint.endswith(":51820"))

    def test_unmanaged_peer_is_preserved(self) -> None:
        # Inject a peer the CLI didn't create, then run a mutating command.
        path = self.mgr._conf_path
        conf = self.mgr.backend.read_file(path)
        conf += (
            "\n[Peer]\n"
            "PublicKey = dW5tYW5hZ2VkLXBlZXIta2V5LXRoYXQtaXMtbm90LW1pbmU9\n"
            "AllowedIPs = 10.8.1.200/32\n"
        )
        self.mgr.backend.write_file(path, conf)

        self.mgr.create_user("alice")

        peers = wg.parse_config(self.mgr.backend.read_file(path)).peers
        allowed = {p.allowed_ips for p in peers}
        self.assertIn("10.8.1.200/32", allowed)  # foreign peer kept
        self.assertIn("10.8.1.2/32", allowed)    # alice added

    def test_deleted_peer_does_not_come_back_as_unmanaged(self) -> None:
        self.mgr.create_user("alice")
        self.mgr.create_user("bob")
        self.mgr.delete_user("alice")
        # A second mutating command re-runs sync(); alice's old peer must not
        # reappear (it used to get reclassified as "foreign" and preserved).
        self.mgr.create_user("carol")
        conf = self.mgr.backend.read_file(self.mgr._conf_path)
        names = {p.comment for p in wg.parse_config(conf).peers}
        self.assertEqual(names, {"bob", "carol"})

    def test_rekeyed_peer_old_key_does_not_leak(self) -> None:
        self.mgr.create_user("alice")
        old_key = self.mgr.db.get_user("alice").public_key
        self.mgr.rekey_user("alice")
        self.mgr.sync()
        conf = self.mgr.backend.read_file(self.mgr._conf_path)
        keys = {p.public_key for p in wg.parse_config(conf).peers}
        self.assertNotIn(old_key, keys)
        self.assertEqual(len(keys), 1)

    def test_create_user_avoids_address_of_foreign_peer(self) -> None:
        # Simulate a peer added directly through the Amnezia app: not in our
        # DB, so create_user must still not hand out its address.
        path = self.mgr._conf_path
        conf = self.mgr.backend.read_file(path)
        conf += (
            "\n[Peer]\n"
            "PublicKey = Zm9yZWlnbi1wZWVyLWtleS1ub3QtbWFuYWdlZC1oZXJlPQ==\n"
            "AllowedIPs = 10.8.1.2/32\n"
        )
        self.mgr.backend.write_file(path, conf)

        user = self.mgr.create_user("alice")
        self.assertNotEqual(user.address, "10.8.1.2/32")

    def test_unknown_user_raises(self) -> None:
        with self.assertRaises(UserNotFoundError):
            self.mgr.set_enabled("ghost", True)

    def test_audit_trail_recorded(self) -> None:
        self.mgr.create_user("alice")
        self.mgr.delete_user("alice")
        actions = [r["action"] for r in self.mgr.db.recent_audit()]
        self.assertIn("create-user", actions)
        self.assertIn("delete-user", actions)

    def test_traffic_limit_parsed_on_create(self) -> None:
        user = self.mgr.create_user("alice", traffic_limit="1GB")
        self.assertEqual(user.traffic_limit_bytes, 1024 ** 3)
        self.assertEqual(user.traffic_used_bytes, 0)

    def test_set_traffic_limit_and_clear(self) -> None:
        self.mgr.create_user("alice")
        user = self.mgr.set_traffic_limit("alice", "500MB")
        self.assertEqual(user.traffic_limit_bytes, 500 * 1024 ** 2)
        user = self.mgr.set_traffic_limit("alice", "unlimited")
        self.assertIsNone(user.traffic_limit_bytes)

    def test_enforce_quotas_accumulates_usage_without_disabling(self) -> None:
        user = self.mgr.create_user("alice", traffic_limit="1GB")
        self.mgr.backend.transfer[user.public_key] = (100, 200)
        report = self.mgr.enforce_quotas()
        self.assertEqual(report.disabled, [])
        alice = self.mgr.db.get_user("alice")
        self.assertEqual(alice.traffic_used_bytes, 300)
        self.assertTrue(alice.enabled)

    def test_enforce_quotas_disables_over_limit_user(self) -> None:
        user = self.mgr.create_user("bob", traffic_limit="1KB")
        self.mgr.backend.transfer[user.public_key] = (2000, 0)
        report = self.mgr.enforce_quotas()
        self.assertEqual(report.disabled, ["bob"])
        bob = self.mgr.db.get_user("bob")
        self.assertFalse(bob.enabled)
        conf = self.mgr.backend.read_file(self.mgr._conf_path)
        self.assertEqual(wg.parse_config(conf).peers, [])

    def test_enforce_quotas_handles_counter_reset(self) -> None:
        user = self.mgr.create_user("alice", traffic_limit="1GB")
        self.mgr.backend.transfer[user.public_key] = (5000, 0)
        self.mgr.enforce_quotas()
        # Interface restarted: raw counter drops below the last-seen value.
        self.mgr.backend.transfer[user.public_key] = (100, 0)
        self.mgr.enforce_quotas()
        alice = self.mgr.db.get_user("alice")
        self.assertEqual(alice.traffic_used_bytes, 5100)


if __name__ == "__main__":
    unittest.main()
