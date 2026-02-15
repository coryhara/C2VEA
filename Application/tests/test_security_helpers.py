import unittest
from unittest.mock import patch

from app.routes.auth_routes import _is_legacy_sha512_hash
from app.routes.poc_routes import _validate_public_url


class SecurityHelpersTest(unittest.TestCase):
    def test_legacy_sha512_hash_detection(self):
        self.assertTrue(_is_legacy_sha512_hash("a" * 128))
        self.assertFalse(_is_legacy_sha512_hash("a" * 127))
        self.assertFalse(_is_legacy_sha512_hash("z" * 128))

    @patch("app.routes.poc_routes.socket.getaddrinfo")
    def test_validate_public_url_allows_public_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (0, 0, 0, "", ("93.184.216.34", 443))
        ]
        self.assertIsNone(_validate_public_url("https://example.com/poc"))

    @patch("app.routes.poc_routes.socket.getaddrinfo")
    def test_validate_public_url_blocks_private_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (0, 0, 0, "", ("10.0.0.5", 443))
        ]
        msg = _validate_public_url("https://internal.example/poc")
        self.assertEqual(msg, "Private or local network addresses are not allowed.")


if __name__ == "__main__":
    unittest.main()
