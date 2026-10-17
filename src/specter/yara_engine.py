"""
YARA-style rule engine for malware signature matching.
Implements a subset of YARA rule syntax: strings, conditions, modifiers.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple


class StringModifier(str, Enum):
    NOCASE = "nocase"
    WIDE = "wide"
    ASCII = "ascii"
    FULLWORD = "fullword"
    XOR = "xor"
    BASE64 = "base64"


@dataclass
class YaraString:
    identifier: str  # e.g. "$s1"
    value: bytes
    modifiers: Set[StringModifier] = field(default_factory=set)
    is_regex: bool = False
    is_hex: bool = False

    def compile_pattern(self) -> re.Pattern | None:
        if not self.is_regex:
            return None
        flags = re.DOTALL
        if StringModifier.NOCASE in self.modifiers:
            flags |= re.IGNORECASE
        try:
            return re.compile(self.value, flags)
        except re.error:
            return None


@dataclass
class YaraMatch:
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Tuple[str, int, bytes]]  # (identifier, offset, matched_data)
    file_hash: str = ""

    @property
    def matched_identifiers(self) -> Set[str]:
        return {s[0] for s in self.strings}


@dataclass
class YaraRule:
    name: str
    namespace: str = "default"
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    strings: List[YaraString] = field(default_factory=list)
    condition: str = "any of them"
    enabled: bool = True

    def __post_init__(self) -> None:
        self._compiled_patterns: Dict[str, re.Pattern | None] = {}
        for s in self.strings:
            self._compiled_patterns[s.identifier] = s.compile_pattern()


class YaraEngine:
    """
    Pure-Python YARA-style rule engine.

    Supports:
    - Text string matching (ASCII and wide-char)
    - Hex byte pattern matching with wildcards (??)
    - Regex string matching
    - nocase, wide, ascii, fullword, xor modifiers
    - Conditions: all of them, any of them, N of them, boolean expressions
    - Rule loading from text format
    - Namespace isolation
    """

    def __init__(self) -> None:
        self._rules: Dict[str, YaraRule] = {}

    def add_rule(self, rule: YaraRule) -> None:
        key = f"{rule.namespace}::{rule.name}"
        self._rules[key] = rule

    def load_rules_text(self, rules_text: str, namespace: str = "default") -> int:
        """Parse and load YARA rules from text format. Returns count of loaded rules."""
        rules = list(self._parse_rules_text(rules_text, namespace))
        for rule in rules:
            self.add_rule(rule)
        return len(rules)

    def scan(self, data: bytes, file_hash: str = "") -> List[YaraMatch]:
        """Scan data against all loaded rules."""
        matches = []
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            match = self._match_rule(rule, data, file_hash)
            if match:
                matches.append(match)
        return matches

    def scan_file(self, path: str) -> List[YaraMatch]:
        with open(path, "rb") as f:
            data = f.read()
        import hashlib
        h = hashlib.sha256(data).hexdigest()
        return self.scan(data, file_hash=h)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def get_rule(self, name: str, namespace: str = "default") -> Optional[YaraRule]:
        return self._rules.get(f"{namespace}::{name}")

    def _match_rule(
        self, rule: YaraRule, data: bytes, file_hash: str
    ) -> Optional[YaraMatch]:
        string_matches: Dict[str, List[Tuple[int, bytes]]] = {}
        for yara_str in rule.strings:
            hits = list(self._find_string_hits(yara_str, data))
            if hits:
                string_matches[yara_str.identifier] = hits

        if not self._evaluate_condition(rule.condition, string_matches, rule.strings):
            return None

        flat_strings = []
        for ident, hits in string_matches.items():
            for offset, matched in hits:
                flat_strings.append((ident, offset, matched))

        return YaraMatch(
            rule_name=rule.name,
            namespace=rule.namespace,
            tags=rule.tags,
            meta=rule.meta,
            strings=flat_strings,
            file_hash=file_hash,
        )

    def _find_string_hits(
        self, yara_str: YaraString, data: bytes
    ) -> Iterator[Tuple[int, bytes]]:
        if yara_str.is_regex:
            pattern = yara_str.compile_pattern()
            if pattern:
                for m in pattern.finditer(data):
                    yield m.start(), m.group()
        elif yara_str.is_hex:
            yield from self._find_hex_pattern(yara_str.value, data)
        else:
            yield from self._find_text_string(yara_str, data)

    def _find_text_string(
        self, yara_str: YaraString, data: bytes
    ) -> Iterator[Tuple[int, bytes]]:
        value = yara_str.value
        nocase = StringModifier.NOCASE in yara_str.modifiers
        wide = StringModifier.WIDE in yara_str.modifiers
        fullword = StringModifier.FULLWORD in yara_str.modifiers
        xor = StringModifier.XOR in yara_str.modifiers

        search_data = data.lower() if nocase else data
        search_value = value.lower() if nocase else value

        if xor:
            yield from self._find_xor_string(value, data)
            return

        if wide:
            wide_value = bytes(b for c in value for b in (c, 0))
            if nocase:
                wide_value_lower = bytes(b for c in value.lower() for b in (c, 0))
                yield from self._find_exact(wide_value_lower, data.lower(), fullword, data, wide_value_lower)
            else:
                yield from self._find_exact(wide_value, data, fullword, data, wide_value)
        else:
            yield from self._find_exact(search_value, search_data, fullword, data, search_value)

    def _find_exact(
        self,
        needle: bytes,
        haystack: bytes,
        fullword: bool,
        original_data: bytes,
        original_needle: bytes,
    ) -> Iterator[Tuple[int, bytes]]:
        start = 0
        while True:
            pos = haystack.find(needle, start)
            if pos == -1:
                break
            if fullword:
                pre = pos == 0 or not (haystack[pos - 1:pos].isalpha() or haystack[pos - 1:pos] == b"_")
                post_idx = pos + len(needle)
                post = post_idx >= len(haystack) or not (haystack[post_idx:post_idx + 1].isalpha() or haystack[post_idx:post_idx + 1] == b"_")
                if pre and post:
                    yield pos, original_data[pos:pos + len(original_needle)]
            else:
                yield pos, original_data[pos:pos + len(original_needle)]
            start = pos + 1

    def _find_hex_pattern(
        self, pattern: bytes, data: bytes
    ) -> Iterator[Tuple[int, bytes]]:
        """
        Match hex patterns with wildcard support.
        Pattern format: decoded bytes where 0x100 marks a wildcard (??).
        We use a special internal format: list of (byte | None) for wildcards.
        """
        # pattern here is the raw hex pattern bytes already compiled
        compiled = self._compile_hex_pattern(pattern)
        if compiled is None:
            return

        pattern_len = len(compiled)
        for i in range(len(data) - pattern_len + 1):
            matched = True
            for j, expected in enumerate(compiled):
                if expected is not None and data[i + j] != expected:
                    matched = False
                    break
            if matched:
                yield i, data[i:i + pattern_len]

    @staticmethod
    def _compile_hex_pattern(hex_str: bytes) -> Optional[List[Optional[int]]]:
        """
        Compile a hex pattern string like "4D 5A ?? 00" into a list of byte values.
        None represents wildcard (??).
        """
        text = hex_str.decode("ascii", errors="ignore").strip()
        compiled = []
        tokens = text.split()
        for token in tokens:
            if token == "??":
                compiled.append(None)
            elif len(token) == 2 and all(c in "0123456789ABCDEFabcdef" for c in token):
                compiled.append(int(token, 16))
            else:
                return None
        return compiled if compiled else None

    def _find_xor_string(
        self, value: bytes, data: bytes
    ) -> Iterator[Tuple[int, bytes]]:
        """Find XOR-encoded string with single-byte keys 1-255."""
        for key in range(1, 256):
            xored = bytes(b ^ key for b in value)
            start = 0
            while True:
                pos = data.find(xored, start)
                if pos == -1:
                    break
                yield pos, xored
                start = pos + 1

    def _evaluate_condition(
        self,
        condition: str,
        matches: Dict[str, List[Tuple[int, bytes]]],
        all_strings: List[YaraString],
    ) -> bool:
        cond = condition.strip().lower()

        if cond == "any of them":
            return len(matches) > 0

        if cond == "all of them":
            return all(s.identifier in matches for s in all_strings)

        # "N of them"
        n_of_them = re.match(r"^(\d+)\s+of\s+them$", cond)
        if n_of_them:
            n = int(n_of_them.group(1))
            return len(matches) >= n

        # "N of ($pattern*)"
        n_of_pattern = re.match(r"^(\d+)\s+of\s+\((\$[a-z_*0-9]+)\)$", cond)
        if n_of_pattern:
            n = int(n_of_pattern.group(1))
            pattern = n_of_pattern.group(2).replace("*", ".*")
            count = sum(
                1 for ident in matches
                if re.match(pattern, ident.lower())
            )
            return count >= n

        # Simple identifier check "$s1"
        if re.match(r"^\$[a-z_0-9]+$", cond):
            return cond in matches

        # Boolean expression: "$s1 and $s2"
        return self._eval_bool_expr(condition, matches)

    def _eval_bool_expr(
        self,
        expr: str,
        matches: Dict[str, List[Tuple[int, bytes]]],
    ) -> bool:
        """Evaluate a simple boolean expression with and/or/not."""
        expr = expr.strip()

        # Handle parentheses
        if expr.startswith("(") and expr.endswith(")"):
            return self._eval_bool_expr(expr[1:-1], matches)

        # Split on 'or' first (lower precedence)
        or_parts = re.split(r"\bor\b", expr, flags=re.IGNORECASE)
        if len(or_parts) > 1:
            return any(self._eval_bool_expr(p, matches) for p in or_parts)

        # Split on 'and'
        and_parts = re.split(r"\band\b", expr, flags=re.IGNORECASE)
        if len(and_parts) > 1:
            return all(self._eval_bool_expr(p, matches) for p in and_parts)

        # Handle 'not'
        not_match = re.match(r"^\s*not\s+(.+)$", expr, re.IGNORECASE)
        if not_match:
            return not self._eval_bool_expr(not_match.group(1), matches)

        # Leaf: identifier reference
        expr = expr.strip()
        if expr.startswith("$"):
            return expr in matches

        # Fallback
        return False

    def _parse_rules_text(
        self, text: str, namespace: str
    ) -> Iterator[YaraRule]:
        """Parse YARA rule text into YaraRule objects using brace-counting."""
        # Remove block comments first
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        # Remove line comments: // not preceded by : (to preserve http://, ftp://)
        text = re.sub(r"(?<!:)//[^\n]*", "", text)

        header_re = re.compile(
            r"rule\s+(\w+)(?:\s*:\s*([\w\s]+?))?\s*\{",
        )
        pos = 0
        while pos < len(text):
            m = header_re.search(text, pos)
            if not m:
                break

            name = m.group(1)
            tags_str = (m.group(2) or "").strip()
            body_start = m.end()  # position after opening '{'

            # Count braces to find matching closing '}'
            depth = 1
            i = body_start
            while i < len(text) and depth > 0:
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                i += 1

            if depth != 0:
                break  # unmatched brace

            body = text[body_start:i - 1]  # content between outer { }
            pos = i

            tags = tags_str.split() if tags_str else []
            meta = self._parse_meta(body)
            strings = self._parse_strings(body)
            condition = self._parse_condition(body)

            yield YaraRule(
                name=name,
                namespace=namespace,
                tags=tags,
                meta=meta,
                strings=strings,
                condition=condition,
            )

    @staticmethod
    def _parse_meta(body: str) -> Dict[str, Any]:
        meta: Dict[str, Any] = {}
        meta_block = re.search(r"meta\s*:(.*?)(?:strings\s*:|condition\s*:)", body, re.DOTALL)
        if not meta_block:
            return meta
        for line in meta_block.group(1).splitlines():
            kv = re.match(r'\s*(\w+)\s*=\s*"([^"]*)"', line)
            if kv:
                meta[kv.group(1)] = kv.group(2)
            kv_num = re.match(r"\s*(\w+)\s*=\s*(\d+)", line)
            if kv_num:
                meta[kv_num.group(1)] = int(kv_num.group(2))
        return meta

    def _parse_strings(self, body: str) -> List[YaraString]:
        strings = []
        strings_block = re.search(r"strings\s*:(.*?)condition\s*:", body, re.DOTALL)
        if not strings_block:
            return strings

        for line in strings_block.group(1).splitlines():
            # Text string: $s1 = "value" nocase wide
            text_match = re.match(r'\s*(\$\w+)\s*=\s*"([^"]*)"(.*)', line)
            if text_match:
                ident = text_match.group(1)
                value = text_match.group(2).encode("utf-8")
                mods_str = text_match.group(3).lower()
                mods: Set[StringModifier] = set()
                for mod in StringModifier:
                    if mod.value in mods_str:
                        mods.add(mod)
                strings.append(YaraString(identifier=ident, value=value, modifiers=mods))
                continue

            # Hex string: $h1 = { 4D 5A ?? 00 }
            hex_match = re.match(r"\s*(\$\w+)\s*=\s*\{([^}]+)\}", line)
            if hex_match:
                ident = hex_match.group(1)
                hex_content = hex_match.group(2).strip()
                strings.append(YaraString(
                    identifier=ident,
                    value=hex_content.encode("ascii"),
                    is_hex=True,
                ))
                continue

            # Regex string: $r1 = /pattern/ nocase
            regex_match = re.match(r"\s*(\$\w+)\s*=\s*/([^/]+)/([a-z]*)", line)
            if regex_match:
                ident = regex_match.group(1)
                pattern = regex_match.group(2)
                flags_str = regex_match.group(3)
                mods = set()
                if "i" in flags_str:
                    mods.add(StringModifier.NOCASE)
                strings.append(YaraString(
                    identifier=ident,
                    value=pattern.encode("utf-8"),
                    modifiers=mods,
                    is_regex=True,
                ))

        return strings

    @staticmethod
    def _parse_condition(body: str) -> str:
        cond_match = re.search(r"condition\s*:(.*?)(?:\}|$)", body, re.DOTALL)
        if cond_match:
            return cond_match.group(1).strip()
        return "any of them"
