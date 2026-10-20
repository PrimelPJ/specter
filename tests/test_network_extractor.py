"""Tests for network indicator extraction."""

import pytest
from specter.network_extractor import (
    NetworkExtractor,
    NetworkIndicatorType,
    _is_private_ip,
    _is_benign_domain,
    _extract_ascii_strings,
    _extract_wide_strings,
)


class TestPrivateIPFilter:
    def test_rfc1918_filtered(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("172.16.5.5") is True
        assert _is_private_ip("192.168.1.100") is True

    def test_loopback_filtered(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_public_ip_not_filtered(self):
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("185.220.101.1") is False
        assert _is_private_ip("45.33.32.156") is False


class TestBenignDomainFilter:
    def test_microsoft_filtered(self):
        assert _is_benign_domain("microsoft.com") is True
        assert _is_benign_domain("update.microsoft.com") is True

    def test_malicious_domain_not_filtered(self):
        assert _is_benign_domain("evil.c2.ru") is False
        assert _is_benign_domain("dropper.xyz") is False


class TestAsciiExtraction:
    def test_extract_simple_string(self):
        data = b"\x00\x00hello world\x00\x00"
        results = list(_extract_ascii_strings(data, min_len=4))
        values = [r[0] for r in results]
        assert any("hello world" in v for v in values)

    def test_min_length_respected(self):
        data = b"ab\x00abcd\x00abcdefgh\x00"
        results = list(_extract_ascii_strings(data, min_len=6))
        for v, _ in results:
            assert len(v) >= 6


class TestWideStringExtraction:
    def test_extract_wide_string(self):
        text = "evil.com"
        # Wide string must be 2-byte aligned; don't add misaligning prefix
        wide = b"".join(bytes([ord(c), 0]) for c in text) + b"\x00\x00"
        data = wide + b"\x00\x00"
        results = list(_extract_wide_strings(data, min_len=4))
        values = [r[0] for r in results]
        assert any("evil.com" in v for v in values)


class TestNetworkExtractor:
    def setup_method(self):
        self.extractor = NetworkExtractor(include_private_ips=False)

    def test_extract_public_ip(self):
        data = b"connecting to 185.220.101.45 for C2\x00"
        result = self.extractor.extract(data)
        ips = [i.value for i in result.ipv4_addresses]
        assert "185.220.101.45" in ips

    def test_private_ip_filtered_by_default(self):
        data = b"connecting to 192.168.1.1 internal\x00"
        result = self.extractor.extract(data)
        ips = [i.value for i in result.ipv4_addresses]
        assert "192.168.1.1" not in ips

    def test_include_private_ips_option(self):
        extractor = NetworkExtractor(include_private_ips=True)
        data = b"host: 192.168.1.1\x00"
        result = extractor.extract(data)
        ips = [i.value for i in result.ipv4_addresses]
        assert "192.168.1.1" in ips

    def test_extract_url(self):
        data = b"download from http://evil.com/drop.exe now\x00"
        result = self.extractor.extract(data)
        urls = [u.value for u in result.urls]
        assert any("evil.com" in u for u in urls)

    def test_extract_domain(self):
        data = b"contact c2server.xyz for instructions\x00"
        result = self.extractor.extract(data)
        domains = [d.value for d in result.domains]
        assert any("c2server.xyz" in d for d in domains)

    def test_extract_email(self):
        data = b"send results to attacker@malicious.ru ok\x00"
        result = self.extractor.extract(data)
        emails = [e.value for e in result.emails]
        assert any("attacker@malicious.ru" in e for e in emails)

    def test_extract_mutex(self):
        data = b"creating mutex Global\\MALWARE_MUTEX_XYZ\x00"
        result = self.extractor.extract(data)
        mutexes = [m.value for m in result.mutexes]
        assert any("MALWARE_MUTEX_XYZ" in m for m in mutexes)

    def test_extract_uri_path(self):
        data = b"GET /upload/payload.php HTTP/1.1\x00"
        result = self.extractor.extract(data)
        uris = [u.value for u in result.uri_paths]
        assert any(".php" in u for u in uris)

    def test_benign_domain_filtered(self):
        data = b"connecting to update.microsoft.com for patch\x00"
        result = self.extractor.extract(data)
        domains = [d.value for d in result.domains]
        assert not any("microsoft.com" in d for d in domains)

    def test_wide_string_extraction(self):
        # Embed URL as wide string
        url = "http://evil.net/gate.php"
        wide_data = b"".join(bytes([ord(c), 0]) for c in url)
        result = self.extractor.extract(b"\x00" * 4 + wide_data + b"\x00\x00\x00\x00")
        all_vals = [u.value for u in result.urls]
        assert any("evil.net" in u for u in all_vals)

    def test_summary_dict(self):
        data = b"GET http://bad.ru/gate.php?id=123 from 45.33.1.2\x00"
        result = self.extractor.extract(data)
        summary = result.summary()
        assert "urls" in summary
        assert "ipv4" in summary
        assert isinstance(summary["suspicious"], int)

    def test_c2_candidates_returned(self):
        data = b"POST http://185.220.101.45/upload HTTP/1.1\x00cmd.exe\x00"
        result = self.extractor.extract(data)
        candidates = self.extractor.get_c2_candidates(result)
        assert len(candidates) > 0

    def test_all_indicators_property(self):
        data = b"evil.ru 185.220.1.1 test@evil.ru\x00"
        result = self.extractor.extract(data)
        all_ind = result.all_indicators
        assert isinstance(all_ind, list)

    def test_extract_from_file(self, tmp_path):
        sample = tmp_path / "sample.bin"
        sample.write_bytes(b"C2: http://command.xyz/beacon POST\x00")
        result = self.extractor.extract_from_file(str(sample))
        assert result.total_bytes_scanned > 0
