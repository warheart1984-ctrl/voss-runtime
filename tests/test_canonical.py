import unittest

from voss.canonical import (
    ProtocolError,
    canonical_bytes,
    loads_strict,
    new_id,
    sha256_hex,
)


class CanonicalTest(unittest.TestCase):
    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ProtocolError):
            loads_strict('{"version": "1", "version": "2"}')

    def test_non_finite_constants_rejected(self):
        for text in ('{"x": NaN}', '{"x": Infinity}', '{"x": -Infinity}'):
            with self.assertRaises(ProtocolError):
                loads_strict(text)

    def test_control_characters_rejected(self):
        with self.assertRaises(ProtocolError):
            canonical_bytes({"a": "bad\x00string"})

    def test_canonical_serialization_is_key_sorted(self):
        a = canonical_bytes({"z": 1, "a": {"y": 2, "x": 3}})
        b = canonical_bytes({"a": {"x": 3, "y": 2}, "z": 1})
        self.assertEqual(a, b)

    def test_sha256_stable(self):
        self.assertEqual(
            sha256_hex({"action": "read", "path": "x"}),
            sha256_hex({"path": "x", "action": "read"}),
        )

    def test_new_id_uniqueness(self):
        self.assertNotEqual(new_id(), new_id())
        self.assertTrue(new_id("cap-").startswith("cap-"))

    def test_nested_duplicate_rejected(self):
        with self.assertRaises(ProtocolError):
            loads_strict('{"a": {"b": 1, "b": 2}}')


if __name__ == "__main__":
    unittest.main()