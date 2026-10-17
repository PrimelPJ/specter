"""
Tests for the YARA-style rule engine.
"""

import pytest

from specter.yara_engine import YaraEngine, YaraRule, YaraString, StringModifier, YaraMatch


BASIC_RULES = """
rule DetectMZ : pe_header {
    meta:
        description = "Detects PE MZ header"
        author = "test"
    strings:
        $mz = { 4D 5A }
        $pe = "PE"
    condition:
        $mz
}

rule DetectHttp {
    strings:
        $url = "http://" nocase
    condition:
        $url
}

rule DetectMultiple {
    strings:
        $s1 = "malware"
        $s2 = "virus"
        $s3 = "trojan"
    condition:
        2 of them
}

rule DetectAll {
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        all of them
}
"""


class TestYaraEngine:
    def setup_method(self):
        self.engine = YaraEngine()

    def test_load_rules_text(self):
        count = self.engine.load_rules_text(BASIC_RULES)
        assert count == 4

    def test_rule_count_after_load(self):
        self.engine.load_rules_text(BASIC_RULES)
        assert self.engine.rule_count == 4

    def test_scan_detects_mz(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"MZ" + b"\x00" * 100
        matches = self.engine.scan(data)
        rule_names = {m.rule_name for m in matches}
        assert "DetectMZ" in rule_names

    def test_scan_no_match(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"\x00" * 200
        matches = self.engine.scan(data)
        assert not any(m.rule_name == "DetectMZ" for m in matches)

    def test_scan_nocase_url(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"Connection: HTTP://evil.example.com/payload"
        matches = self.engine.scan(data)
        assert any(m.rule_name == "DetectHttp" for m in matches)

    def test_n_of_them_condition(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"malware virus hello world"
        matches = self.engine.scan(data)
        assert any(m.rule_name == "DetectMultiple" for m in matches)

    def test_n_of_them_not_enough(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"malware hello world"
        matches = self.engine.scan(data)
        assert not any(m.rule_name == "DetectMultiple" for m in matches)

    def test_all_of_them_condition(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"alpha beta gamma"
        matches = self.engine.scan(data)
        assert any(m.rule_name == "DetectAll" for m in matches)

    def test_all_of_them_partial(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"alpha only"
        matches = self.engine.scan(data)
        assert not any(m.rule_name == "DetectAll" for m in matches)

    def test_match_contains_string_offsets(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"MZ" + b"\x00" * 100
        matches = self.engine.scan(data)
        mz_match = next((m for m in matches if m.rule_name == "DetectMZ"), None)
        assert mz_match is not None
        assert len(mz_match.strings) > 0
        offset, matched = mz_match.strings[0][1], mz_match.strings[0][2]
        assert offset >= 0

    def test_match_rule_tags(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"MZ" + b"\x00" * 100
        matches = self.engine.scan(data)
        mz_match = next(m for m in matches if m.rule_name == "DetectMZ")
        assert "pe_header" in mz_match.tags

    def test_match_meta(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"MZ" + b"\x00" * 100
        matches = self.engine.scan(data)
        mz_match = next(m for m in matches if m.rule_name == "DetectMZ")
        assert mz_match.meta.get("author") == "test"

    def test_hex_pattern_with_wildcard(self):
        rule_text = """
rule HexWildcard {
    strings:
        $h = { 4D 5A ?? 00 }
    condition:
        $h
}
"""
        self.engine.load_rules_text(rule_text)
        data = b"MZ\x90\x00" + b"\x00" * 50
        matches = self.engine.scan(data)
        assert any(m.rule_name == "HexWildcard" for m in matches)

    def test_hex_no_match(self):
        rule_text = """
rule HexNoMatch {
    strings:
        $h = { FF FF FF FF }
    condition:
        $h
}
"""
        self.engine.load_rules_text(rule_text)
        data = b"MZ" + b"\x00" * 100
        matches = self.engine.scan(data)
        assert not any(m.rule_name == "HexNoMatch" for m in matches)

    def test_namespace_isolation(self):
        rule_text = """
rule TestRule {
    strings:
        $s = "test"
    condition:
        $s
}
"""
        self.engine.load_rules_text(rule_text, namespace="ns1")
        self.engine.load_rules_text(rule_text, namespace="ns2")
        assert self.engine.rule_count == 2

    def test_get_rule(self):
        self.engine.load_rules_text(BASIC_RULES)
        rule = self.engine.get_rule("DetectMZ")
        assert rule is not None
        assert rule.name == "DetectMZ"

    def test_disabled_rule_not_matched(self):
        self.engine.load_rules_text(BASIC_RULES)
        rule = self.engine.get_rule("DetectMZ")
        rule.enabled = False
        data = b"MZ" + b"\x00" * 100
        matches = self.engine.scan(data)
        assert not any(m.rule_name == "DetectMZ" for m in matches)

    def test_xor_string_detection(self):
        rule_text = """
rule XorDetect {
    strings:
        $s = "secret" xor
    condition:
        $s
}
"""
        self.engine.load_rules_text(rule_text)
        # XOR "secret" with key 0x42
        plaintext = b"secret"
        xored = bytes(b ^ 0x42 for b in plaintext)
        data = b"\x00" * 50 + xored + b"\x00" * 50
        matches = self.engine.scan(data)
        assert any(m.rule_name == "XorDetect" for m in matches)

    def test_regex_matching(self):
        rule_text = """
rule RegexTest {
    strings:
        $r = /[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/
    condition:
        $r
}
"""
        self.engine.load_rules_text(rule_text)
        data = b"Connection from 192.168.1.100 detected"
        matches = self.engine.scan(data)
        assert any(m.rule_name == "RegexTest" for m in matches)

    def test_boolean_and_condition(self):
        rule_text = """
rule BoolAnd {
    strings:
        $a = "alpha"
        $b = "beta"
    condition:
        $a and $b
}
"""
        self.engine.load_rules_text(rule_text)
        data = b"alpha and beta together"
        matches = self.engine.scan(data)
        assert any(m.rule_name == "BoolAnd" for m in matches)

        data_partial = b"only alpha here"
        matches_partial = self.engine.scan(data_partial)
        assert not any(m.rule_name == "BoolAnd" for m in matches_partial)

    def test_file_hash_in_match(self):
        self.engine.load_rules_text(BASIC_RULES)
        data = b"MZ" + b"\x00" * 64
        matches = self.engine.scan(data, file_hash="abc123")
        mz = next(m for m in matches if m.rule_name == "DetectMZ")
        assert mz.file_hash == "abc123"
