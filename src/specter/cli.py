"""
Command-line interface for Specter malware analysis sandbox.
Provides subcommands for static PE analysis, YARA scanning, and string extraction.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def _load_sample(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        print(f"[error] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    return p.read_bytes()


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str))


def cmd_analyze(args: argparse.Namespace) -> int:
    from specter.pe_parser import PEParser
    from specter.entropy import EntropyAnalyzer
    from specter.network_extractor import NetworkExtractor
    from specter.string_extractor import StringExtractor

    data = _load_sample(args.file)

    print(f"[*] Analyzing: {args.file} ({len(data):,} bytes)")

    # PE analysis
    parser = PEParser()
    pe = parser.parse(data)
    if pe is None:
        print("[-] Not a valid PE file")
        if not args.force:
            return 1
    else:
        print(f"[+] PE Type    : {pe.file_type}")
        print(f"[+] Machine    : {pe.machine}")
        print(f"[+] Timestamp  : {pe.compile_timestamp}")
        print(f"[+] Sections   : {len(pe.sections)}")
        print(f"[+] Imports    : {sum(len(m.functions) for m in pe.imports)} from {len(pe.imports)} DLLs")
        if pe.is_packed:
            print(f"[!] PACKED     : {pe.packer_hint}")
        if pe.is_dotnet:
            print("[+] .NET assembly detected")
        if pe.has_tls:
            print("[!] TLS callbacks present (anti-debug)")
        print()
        for sec in pe.sections:
            flag = " [HIGH ENTROPY]" if sec.entropy > 7.0 else ""
            print(f"    Section {sec.name:<10} VA=0x{sec.virtual_address:08x} "
                  f"size={sec.raw_size:8d} entropy={sec.entropy:.2f}{flag}")
        print()

    # Section entropy
    ea = EntropyAnalyzer()
    block_results = ea.analyze_blocks(data, block_size=512)
    high_blocks = [b for b in block_results if b.entropy > 7.2]
    if high_blocks:
        print(f"[!] {len(high_blocks)} high-entropy blocks (possible packing/encryption)")

    # String extraction
    print("\n[*] String extraction...")
    se = StringExtractor(min_length=6, brute_xor=not args.no_xor)
    str_result = se.extract(data)
    print(f"    Total strings : {len(str_result.strings)}")
    print(f"    Suspicious    : {len(str_result.suspicious())}")
    print(f"    Base64 decoded: {len(str_result.base64_decoded)}")
    if not args.quiet:
        api_calls = [s.value for s in str_result.strings if s.category.value == "api_call"]
        if api_calls:
            print(f"\n[+] Notable API calls:")
            for api in sorted(set(api_calls))[:20]:
                print(f"    {api}")

    # Network indicators
    print("\n[*] Network indicators...")
    ne = NetworkExtractor()
    net_result = ne.extract(data)
    summary = net_result.summary()
    for k, v in summary.items():
        if v > 0:
            print(f"    {k:<14}: {v}")
    if not args.quiet:
        for ind in net_result.suspicious_indicators[:20]:
            print(f"    [{ind.indicator_type.value}] {ind.value}")

    if args.json:
        output: Dict[str, Any] = {
            "file": args.file,
            "size": len(data),
            "strings": {
                "total": len(str_result.strings),
                "suspicious": [s.value for s in str_result.suspicious()[:50]],
                "api_calls": sorted({s.value for s in str_result.strings if s.category.value == "api_call"}),
            },
            "network": {
                "ips": [i.value for i in net_result.ipv4_addresses],
                "domains": [d.value for d in net_result.domains],
                "urls": [u.value for u in net_result.urls],
            },
        }
        if pe is not None:
            output["pe"] = {
                "machine": pe.machine,
                "is_packed": pe.is_packed,
                "packer": pe.packer_hint,
                "is_dotnet": pe.is_dotnet,
                "sections": [
                    {"name": s.name, "entropy": round(s.entropy, 2), "size": s.raw_size}
                    for s in pe.sections
                ],
            }
        with open(args.json, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"\n[+] JSON report written to {args.json}")

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from specter.yara_engine import YaraEngine

    engine = YaraEngine()
    rule_count = 0

    rule_paths: List[str] = []
    if args.rules:
        rule_paths.extend(args.rules)
    else:
        # Default rules directory
        default_rules = Path(__file__).parent.parent.parent / "rules"
        if default_rules.is_dir():
            rule_paths.extend(str(p) for p in default_rules.glob("*.yar"))

    for rp in rule_paths:
        p = Path(rp)
        if p.is_dir():
            for yar in p.glob("**/*.yar"):
                loaded = engine.load_rules_from_file(str(yar))
                rule_count += loaded
        elif p.exists():
            loaded = engine.load_rules_from_file(str(p))
            rule_count += loaded

    if rule_count == 0:
        print("[error] No rules loaded", file=sys.stderr)
        return 1

    print(f"[*] Loaded {rule_count} rules")

    targets: List[str] = []
    for t in args.target:
        p = Path(t)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file():
                    targets.append(str(child))
        else:
            targets.append(t)

    total_matches = 0
    for target in targets:
        try:
            data = Path(target).read_bytes()
        except OSError as exc:
            print(f"[error] Cannot read {target}: {exc}", file=sys.stderr)
            continue

        matches = engine.scan_data(data)
        if matches:
            total_matches += len(matches)
            print(f"\n[MATCH] {target}")
            for m in matches:
                print(f"  Rule   : {m.rule_name} [{', '.join(m.tags)}]")
                for ident, offset, matched_bytes in m.strings[:5]:
                    try:
                        preview = matched_bytes[:32].decode("ascii", errors="replace")
                    except Exception:
                        preview = matched_bytes[:32].hex()
                    print(f"  String : {ident} @ 0x{offset:08x} = {preview!r}")
        elif not args.quiet:
            print(f"[    ] {target}")

    print(f"\n[*] Total matches: {total_matches} across {len(targets)} file(s)")
    return 0 if total_matches > 0 or not args.fail_on_no_match else 1


def cmd_strings(args: argparse.Namespace) -> int:
    from specter.string_extractor import StringExtractor, StringCategory

    data = _load_sample(args.file)
    se = StringExtractor(
        min_length=args.min_length,
        decode_base64=not args.no_base64,
        brute_xor=not args.no_xor,
    )
    result = se.extract(data)

    category_filter = args.category.lower() if args.category else None

    printed = 0
    for s in result.strings:
        if category_filter and s.category.value != category_filter:
            continue
        if args.suspicious_only and not s.is_suspicious:
            continue
        enc = f"[{s.encoding.value}]"
        notes = " | " + "; ".join(s.notes) if s.notes else ""
        print(f"0x{s.offset:08x}  {enc:<12}  {s.category.value:<12}  {s.printable_value}{notes}")
        printed += 1
        if args.limit and printed >= args.limit:
            print(f"... truncated at {args.limit}")
            break

    print(f"\n--- {printed} strings printed ---")
    if result.base64_decoded:
        print(f"\nBase64 payloads decoded: {len(result.base64_decoded)}")
        for raw, decoded in result.base64_decoded[:5]:
            print(f"  {raw[:40]}... -> {len(decoded)} bytes")

    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    import hashlib
    data = _load_sample(args.file)
    print(f"MD5    : {hashlib.md5(data).hexdigest()}")
    print(f"SHA1   : {hashlib.sha1(data).hexdigest()}")
    print(f"SHA256 : {hashlib.sha256(data).hexdigest()}")
    print(f"Size   : {len(data):,} bytes")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="specter",
        description="Specter - Static malware analysis sandbox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="specter 1.0.0")
    sub = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = sub.add_parser("analyze", help="Full static analysis of a PE/binary file")
    p_analyze.add_argument("file", help="Path to sample")
    p_analyze.add_argument("-q", "--quiet", action="store_true", help="Suppress detailed output")
    p_analyze.add_argument("--json", metavar="OUTPUT", help="Write JSON report to file")
    p_analyze.add_argument("--no-xor", action="store_true", help="Skip XOR brute-force")
    p_analyze.add_argument("--force", action="store_true", help="Analyze even if not a PE file")
    p_analyze.set_defaults(func=cmd_analyze)

    # scan
    p_scan = sub.add_parser("scan", help="Scan files with YARA rules")
    p_scan.add_argument("target", nargs="+", help="File(s) or directory to scan")
    p_scan.add_argument("-r", "--rules", nargs="*", metavar="RULE", help="Rule file(s) or directory")
    p_scan.add_argument("-q", "--quiet", action="store_true", help="Show only matches")
    p_scan.add_argument("--fail-on-no-match", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    # strings
    p_strings = sub.add_parser("strings", help="Extract strings from a binary")
    p_strings.add_argument("file", help="Path to sample")
    p_strings.add_argument("-m", "--min-length", type=int, default=4)
    p_strings.add_argument("-c", "--category", help="Filter by category (path/api_call/network/...)")
    p_strings.add_argument("-s", "--suspicious-only", action="store_true")
    p_strings.add_argument("--no-base64", action="store_true")
    p_strings.add_argument("--no-xor", action="store_true")
    p_strings.add_argument("-n", "--limit", type=int, help="Max strings to print")
    p_strings.set_defaults(func=cmd_strings)

    # hash
    p_hash = sub.add_parser("hash", help="Print cryptographic hashes")
    p_hash.add_argument("file")
    p_hash.set_defaults(func=cmd_hash)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
