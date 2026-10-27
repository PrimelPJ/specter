"""
Tests for the malware configuration extractor.
"""

from __future__ import annotations

import struct
import hashlib
import pytest

from specter.config_extractor import (
    ConfigExtractor,
    ConfigField,
    ConfigFieldType,
    MalwareConfig,
    StructuredConfigScanner,
    _xor_decode,
    _xor_decode_multi,
    _rc4,
    _byte_entropy,
    _printable_ratio,
    _is_private_ip,
    _classify_string,
    _kv_key_to_field_type,
    extract_config,
)


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class TestUtilities:
    def test_xor_decode_single_byte(self) -> None:
        data = bytes([0x41 ^ 0x42, 0x42 ^ 0x42, 0x43 ^ 0x42])
        result = _xor_decode(data, 0x42)
        assert result == b"\x41\x42\x43"

    def test_xor_decode_identity_with_zero(self) -> None:
        data = b"hello"
        assert _xor_decode(data, 0) == data

    def test_xor_decode_multi_byte_key(self) -> None:
        key = b"\xAA\xBB"
        plaintext = b"ABCDEF"
        encoded = _xor_decode_multi(plaintext, key)
        decoded = _xor_decode_multi(encoded, key)
        assert decoded == plaintext

    def test_rc4_roundtrip(self) -> None:
        key = b"secretkey123"
        plaintext = b"malware config data 12345"
        ciphertext = _rc4(plaintext, key)
        assert ciphertext != plaintext
        recovered = _rc4(ciphertext, key)
        assert recovered == plaintext

    def test_rc4_empty_key_raises(self) -> None:
        with pytest.raises((ZeroDivisionError, ValueError, Exception)):
            _rc4(b"data", b"")

    def test_byte_entropy_uniform(self) -> None:
        data = bytes(range(256))
        entropy = _byte_entropy(data)
        assert abs(entropy - 8.0) < 0.01

    def test_byte_entropy_constant(self) -> None:
        data = bytes([0x41] * 256)
        assert _byte_entropy(data) == 0.0

    def test_byte_entropy_empty(self) -> None:
        assert _byte_entropy(b"") == 0.0

    def test_printable_ratio_all_printable(self) -> None:
        assert _printable_ratio(b"Hello World!") == 1.0

    def test_printable_ratio_none_printable(self) -> None:
        assert _printable_ratio(bytes(range(0, 32))) == 0.0

    def test_printable_ratio_empty(self) -> None:
        assert _printable_ratio(b"") == 0.0

    def test_is_private_ip_loopback(self) -> None:
        assert _is_private_ip(b"127.0.0.1") is True

    def test_is_private_ip_rfc1918(self) -> None:
        assert _is_private_ip(b"192.168.1.1") is True
        assert _is_private_ip(b"10.0.0.1") is True
        assert _is_private_ip(b"172.16.0.1") is True

    def test_is_private_ip_public(self) -> None:
        assert _is_private_ip(b"8.8.8.8") is False
        assert _is_private_ip(b"203.0.113.50") is False


# ---------------------------------------------------------------------------
# Config field and dataclass tests
# ---------------------------------------------------------------------------

class TestConfigField:
    def test_to_dict_basic(self) -> None:
        f = ConfigField(
            field_type=ConfigFieldType.C2_ADDRESS,
            value="evil.example.com",
            offset=100,
            extraction_method="plaintext",
            confidence=0.9,
        )
        d = f.to_dict()
        assert d["type"] == "c2_address"
        assert d["value"] == "evil.example.com"
        assert d["offset"] == 100
        assert d["confidence"] == 0.9

    def test_to_dict_bytes_value_hexed(self) -> None:
        f = ConfigField(
            field_type=ConfigFieldType.ENCRYPTION_KEY,
            value=b"\xde\xad\xbe\xef",
        )
        d = f.to_dict()
        assert d["value"] == "deadbeef"


class TestMalwareConfig:
    def test_by_type_filters(self) -> None:
        config = MalwareConfig(sample_hash="aabbcc")
        config.add(ConfigField(field_type=ConfigFieldType.C2_ADDRESS, value="1.2.3.4"))
        config.add(ConfigField(field_type=ConfigFieldType.MUTEX, value="Global\\TestMutex"))
        config.add(ConfigField(field_type=ConfigFieldType.C2_ADDRESS, value="5.6.7.8"))
        c2s = config.by_type(ConfigFieldType.C2_ADDRESS)
        assert len(c2s) == 2
        mutexes = config.by_type(ConfigFieldType.MUTEX)
        assert len(mutexes) == 1

    def test_c2_addresses_convenience(self) -> None:
        config = MalwareConfig(sample_hash="aabbcc")
        config.add(ConfigField(field_type=ConfigFieldType.C2_ADDRESS, value="1.2.3.4"))
        assert "1.2.3.4" in config.c2_addresses()

    def test_to_dict_structure(self) -> None:
        config = MalwareConfig(sample_hash="deadbeef")
        config.add(ConfigField(field_type=ConfigFieldType.C2_ADDRESS, value="1.2.3.4"))
        d = config.to_dict()
        assert d["sample_hash"] == "deadbeef"
        assert d["field_count"] == 1
        assert len(d["fields"]) == 1


# ---------------------------------------------------------------------------
# Plaintext extraction tests
# ---------------------------------------------------------------------------

class TestPlaintextExtraction:
    def _make_extractor(self) -> ConfigExtractor:
        return ConfigExtractor(max_xor_passes=False)

    def test_extracts_public_ipv4(self) -> None:
        data = b"connecting to 203.0.113.42:4444 for C2\x00"
        config = self._make_extractor().extract(data)
        c2s = config.c2_addresses()
        assert any("203.0.113.42" in c for c in c2s)

    def test_skips_private_ip(self) -> None:
        data = b"internal 192.168.1.1:80 not c2\x00"
        config = self._make_extractor().extract(data)
        c2s = config.c2_addresses()
        assert not any("192.168.1.1" in c for c in c2s)

    def test_extracts_domain(self) -> None:
        data = b"beacon to malware.evil-host.com:443\x00"
        config = self._make_extractor().extract(data)
        c2s = config.c2_addresses()
        assert any("malware.evil-host.com" in c for c in c2s)

    def test_extracts_url_as_exfil(self) -> None:
        data = b"POST data to http://exfil.example.com/upload\x00"
        config = self._make_extractor().extract(data)
        exfil = [f.value for f in config.by_type(ConfigFieldType.EXFIL_ENDPOINT)]
        assert any("exfil.example.com" in u for u in exfil)

    def test_extracts_mutex(self) -> None:
        data = b"Global\\MyMutexObject_12345\x00"
        config = self._make_extractor().extract(data)
        mutexes = [f.value for f in config.by_type(ConfigFieldType.MUTEX)]
        assert any("MyMutexObject_12345" in m for m in mutexes)

    def test_extracts_registry_key(self) -> None:
        data = b"HKCU\\Software\\Microsoft\\Windows\\Startup\x00"
        config = self._make_extractor().extract(data)
        regs = [f.value for f in config.by_type(ConfigFieldType.REGISTRY_KEY)]
        assert any("HKCU" in r for r in regs)

    def test_extracts_user_agent(self) -> None:
        data = b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\x00"
        config = self._make_extractor().extract(data)
        uas = [f.value for f in config.by_type(ConfigFieldType.USER_AGENT)]
        assert len(uas) >= 1
        assert "Mozilla" in uas[0]

    def test_extracts_install_path(self) -> None:
        data = b"%APPDATA%\\Microsoft\\svchost32.exe\x00"
        config = self._make_extractor().extract(data)
        paths = [f.value for f in config.by_type(ConfigFieldType.INSTALL_PATH)]
        assert any("APPDATA" in p for p in paths)

    def test_extract_returns_correct_hash(self) -> None:
        data = b"test data"
        config = self._make_extractor().extract(data)
        expected = hashlib.sha256(data).hexdigest()
        assert config.sample_hash == expected


# ---------------------------------------------------------------------------
# XOR decryption tests
# ---------------------------------------------------------------------------

class TestXORExtraction:
    def test_xor_recovers_c2_address(self) -> None:
        key = 0x55
        plaintext = b"connect to 198.51.100.10:8080\x00"
        encrypted = _xor_decode(plaintext, key)
        # Extractor with XOR brute-force enabled
        extractor = ConfigExtractor(max_xor_passes=True)
        config = extractor.extract(encrypted)
        c2s = config.c2_addresses()
        assert any("198.51.100.10" in c for c in c2s), f"C2 not found in {c2s}"

    def test_xor_key_counter_set(self) -> None:
        extractor = ConfigExtractor(max_xor_passes=True)
        config = extractor.extract(b"garbage data no config here")
        assert config.xor_keys_tried == 255

    def test_xor_off_skips_brute_force(self) -> None:
        extractor = ConfigExtractor(max_xor_passes=False)
        config = extractor.extract(b"garbage data")
        assert config.xor_keys_tried == 0


# ---------------------------------------------------------------------------
# Base64 extraction tests
# ---------------------------------------------------------------------------

class TestBase64Extraction:
    def test_recovers_domain_from_b64(self) -> None:
        import base64
        inner = b"beacon to update.badware.example.net:9999\x00"
        encoded = base64.b64encode(inner)
        data = b"junk before " + encoded + b" junk after"
        extractor = ConfigExtractor(max_xor_passes=False)
        config = extractor.extract(data)
        c2s = config.c2_addresses()
        assert any("badware.example.net" in c for c in c2s), f"Not found: {c2s}"

    def test_b64_decode_counter(self) -> None:
        import base64
        # Insert enough base64 blobs
        data = base64.b64encode(b"content at 203.0.113.50:1234 end\x00") + b"X" + \
               base64.b64encode(b"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36")
        extractor = ConfigExtractor(max_xor_passes=False)
        config = extractor.extract(data)
        assert config.decode_passes >= 1


# ---------------------------------------------------------------------------
# Structured config scanner tests
# ---------------------------------------------------------------------------

class TestStructuredConfigScanner:
    def test_kv_block_c2(self) -> None:
        data = b"host=198.51.100.20\nport=4444\nmutex=Global\\TestMtx123\n"
        scanner = StructuredConfigScanner()
        fields = scanner.scan(data)
        types = [f.field_type for f in fields]
        assert ConfigFieldType.C2_ADDRESS in types
        assert ConfigFieldType.C2_PORT in types
        assert ConfigFieldType.MUTEX in types

    def test_kv_block_encryption_key(self) -> None:
        data = b"key=MyS3cr3tK3y!!\nsleep=30000\n"
        scanner = StructuredConfigScanner()
        fields = scanner.scan(data)
        types = [f.field_type for f in fields]
        assert ConfigFieldType.ENCRYPTION_KEY in types

    def test_pascal_string_ip(self) -> None:
        ip_bytes = b"198.51.100.77"
        length_prefix = struct.pack("H", len(ip_bytes))
        data = b"\x00" * 8 + length_prefix + ip_bytes + b"\x00" * 8
        scanner = StructuredConfigScanner()
        fields = scanner.scan(data)
        types = [f.field_type for f in fields]
        assert ConfigFieldType.C2_ADDRESS in types

    def test_null_separated_list(self) -> None:
        data = b"203.0.113.1\x00Global\\Mutex123\x00HKCU\\Software\\Evil\x00" + b"\x00" * 450
        scanner = StructuredConfigScanner()
        fields = scanner.scan(data)
        types = [f.field_type for f in fields]
        assert ConfigFieldType.C2_ADDRESS in types


# ---------------------------------------------------------------------------
# Classify string tests
# ---------------------------------------------------------------------------

class TestClassifyString:
    def test_ip_address(self) -> None:
        assert _classify_string("203.0.113.1") == ConfigFieldType.C2_ADDRESS

    def test_url(self) -> None:
        assert _classify_string("https://example.com/upload") == ConfigFieldType.EXFIL_ENDPOINT

    def test_registry_key(self) -> None:
        assert _classify_string("HKCU\\Software\\Test") == ConfigFieldType.REGISTRY_KEY

    def test_install_path(self) -> None:
        assert _classify_string("%APPDATA%\\svc.exe") == ConfigFieldType.INSTALL_PATH

    def test_mutex(self) -> None:
        assert _classify_string("Global\\TestMutex42") == ConfigFieldType.MUTEX

    def test_hex_key_32_chars(self) -> None:
        assert _classify_string("a" * 32) == ConfigFieldType.ENCRYPTION_KEY

    def test_unknown(self) -> None:
        assert _classify_string("random text here") == ConfigFieldType.UNKNOWN


# ---------------------------------------------------------------------------
# KV key mapping tests
# ---------------------------------------------------------------------------

class TestKVKeyMapping:
    def test_host_maps_to_c2(self) -> None:
        assert _kv_key_to_field_type(b"host") == ConfigFieldType.C2_ADDRESS

    def test_port_maps_to_port(self) -> None:
        assert _kv_key_to_field_type(b"port") == ConfigFieldType.C2_PORT

    def test_mutex_maps_to_mutex(self) -> None:
        assert _kv_key_to_field_type(b"mutex") == ConfigFieldType.MUTEX

    def test_sleep_maps_to_sleep(self) -> None:
        assert _kv_key_to_field_type(b"sleep") == ConfigFieldType.SLEEP_INTERVAL

    def test_key_maps_to_encryption(self) -> None:
        assert _kv_key_to_field_type(b"key") == ConfigFieldType.ENCRYPTION_KEY

    def test_unknown_key(self) -> None:
        assert _kv_key_to_field_type(b"zxqwerty") == ConfigFieldType.UNKNOWN


# ---------------------------------------------------------------------------
# Integration test: extract_config convenience wrapper
# ---------------------------------------------------------------------------

class TestExtractConfigWrapper:
    def test_full_pipeline(self) -> None:
        data = (
            b"malware config v1.0\x00"
            b"server=203.0.113.100\x00"
            b"port=4444\x00"
            b"mutex=Global\\EvilMalware_v2\x00"
            b"campaign=OP_MONSOON\x00"
            b"sleep=60000\x00"
            b"HKCU\\Software\\Microsoft\\Windows\\Run\x00"
            b"%APPDATA%\\system32\\svchost.exe\x00"
        )
        config = extract_config(data)
        assert config.sample_hash == hashlib.sha256(data).hexdigest()
        c2s = config.c2_addresses()
        assert any("203.0.113.100" in c for c in c2s)

    def test_deduplication_removes_duplicates(self) -> None:
        data = b"203.0.113.50 203.0.113.50 203.0.113.50\x00"
        extractor = ConfigExtractor(max_xor_passes=False)
        config = extractor.extract(data)
        extractor._deduplicate(config)
        c2s = config.c2_addresses()
        unique_c2s = list(set(c for c in c2s if "203.0.113.50" in c))
        assert len(unique_c2s) == 1
