#!/usr/bin/env python3

from __future__ import annotations
import argparse
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional

# Colors / pretty output

_COLOR = True

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"

def _c(text: str, *codes: str) -> str:
    """Wrap text in ANSI codes, only if color is on"""
    if not _COLOR or not codes:
        return text
    return "".join(codes) + text + RESET

def info(msg: str) -> None:
    print(f"{_c('[*]', BLUE, BOLD)} {msg}")

def warn(msg: str) -> None:
    sys.stdout.flush()
    print(f"{_c('[!]', YELLOW, BOLD)} {msg}", file=sys.stderr)

def error(msg: str) -> None:
    sys.stdout.flush()
    print(f"{_c('[-]', RED, BOLD)} {msg}", file=sys.stderr)

# Core

@dataclass
class SubnetResult:
    """Holds every computed value for a single IP/prefix calculation"""

    ip: str
    prefix: int
    mask: str
    wildcard: str
    network: str
    broadcast: str
    first_host: str
    last_host: str
    usable_hosts: int
    total_addresses: int
    binary_ip: str
    binary_mask: str
    interesting_octet_index: int # 1-indexed
    interesting_octet_value: int
    magic_number: int

    def as_dict(self) -> dict:
        return asdict(self)

def _prefix_to_mask_int(prefix: int) -> int:
    """Convert a prefix length 0-32 into a 32-bit mask integer"""
    if prefix == 0:
        return 0
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF

def _int_to_dotted(value: int) -> str:
    """Convert a 32-bit integer into dotted-decimal notation"""
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))

def _int_to_binary_dotted(value: int) -> str:
    """Convert a 32-bit integer into dotted binary"""
    return ".".join(
        format((value >> shift) & 0xFF, "08b") for shift in (24, 16, 8, 0)
    )

def _octets(value: int) -> List[int]:
    """Split a 32-bit integer into its 4 octets, most significant first"""
    return [(value >> shift) & 0xFF for shift in (24, 16, 8, 0)]

def _color_bits(binary_dotted: str, prefix: int) -> str:
    """Network bits in green, host bits dimmed"""
    out = []
    bit = 0
    for ch in binary_dotted:
        if ch == ".":
            out.append(ch)
            continue
        out.append(_c(ch, GREEN) if bit < prefix else _c(ch, DIM))
        bit += 1
    return "".join(out)

# Validation

def parse_cidr(cidr: str) -> tuple[str, int]:
    """Parse a string like '192.168.1.102/27' into ('192.168.1.102', 27)
    raises ValueError with a clear msg on anything malformed"""
    cidr = cidr.strip()
    if "/" not in cidr:
        raise ValueError(
            f"'{cidr}' is missing a prefix. Expected format x.x.x.x/n (e.g. 192.168.1.102/24)"
        )
    ip_part, prefix_part = cidr.rsplit("/", 1)

    # isdigit() alone lets through things like '²' and arabic-indic digits
    if not (prefix_part.isascii() and prefix_part.isdigit()):
        raise ValueError(f"'{prefix_part}' is not a valid prefix length.")
    prefix = int(prefix_part)

    if not 0 <= prefix <= 32:
        raise ValueError(f"Prefix /{prefix} is out of range. Must be between /0 and /32")

    try:
        ipaddress.IPv4Address(ip_part)
    except ipaddress.AddressValueError:
        raise ValueError(f"'{ip_part}' is not a valid IPv4 address.") from None

    return ip_part, prefix

# Main calculation

def calculate(ip_str: str, prefix: int) -> SubnetResult:
    """Run the full subnet calculation for a given IP and prefix length"""

    ip_int = int(ipaddress.IPv4Address(ip_str))
    mask_int = _prefix_to_mask_int(prefix)
    wildcard_int = (~mask_int) & 0xFFFFFFFF

    network_int = ip_int & mask_int
    broadcast_int = network_int | wildcard_int
    total_addresses = 2 ** (32 - prefix)

    # RFC 3021 (/31) and host routes (/32) are special cases.
    if prefix == 32:
        first_host_int = network_int
        last_host_int = network_int
        usable_hosts = 1
    elif prefix == 31:
        first_host_int = network_int
        last_host_int = broadcast_int
        usable_hosts = 2
    else:
        first_host_int = network_int + 1
        last_host_int = broadcast_int - 1
        usable_hosts = total_addresses - 2

    # Find the "interesting octet": the first octet (left to right) whose
    # mask value is not 255. if every octet is 255, we're at /32 -> default
    # to the last octet for display purposes
    mask_octets = _octets(mask_int)
    interesting_idx = 4
    interesting_val = mask_octets[3]
    for i, octet in enumerate(mask_octets):
        if octet != 255:
            interesting_idx = i + 1
            interesting_val = octet
            break

    magic_number = 256 - interesting_val

    return SubnetResult(
        ip=ip_str,
        prefix=prefix,
        mask=_int_to_dotted(mask_int),
        wildcard=_int_to_dotted(wildcard_int),
        network=_int_to_dotted(network_int),
        broadcast=_int_to_dotted(broadcast_int),
        first_host=_int_to_dotted(first_host_int),
        last_host=_int_to_dotted(last_host_int),
        usable_hosts=usable_hosts,
        total_addresses=total_addresses,
        binary_ip=_int_to_binary_dotted(ip_int),
        binary_mask=_int_to_binary_dotted(mask_int),
        interesting_octet_index=interesting_idx,
        interesting_octet_value=interesting_val,
        magic_number=magic_number,
    )

# Step-by-step 'magic number method' explanation

def explain(result: SubnetResult) -> str:
    """
    Produce a human-readable, step-by-step walkthrough of the magic number method
    for this result, the same steps used to solve it by hand
    """
    idx = result.interesting_octet_index
    magic = result.magic_number
    host_octets = [int(o) for o in result.ip.split(".")]
    host_val = host_octets[idx - 1]

    lines: List[str] = []

    def step(n: int, title: str) -> None:
        lines.append(f"{_c(f'[{n}]', CYAN, BOLD)} {_c(title, BOLD)}")

    def detail(text: str = "") -> None:
        lines.append(f"    {text}" if text else "")

    lines.append(f"{_c('[*]', BLUE, BOLD)} Walkthrough for {_c(f'{result.ip}/{result.prefix}', BOLD)}")
    lines.append(_c("─" * 60, DIM))

    # Step 1: mask
    full_octets = result.prefix // 8
    remainder_bits = result.prefix % 8
    step(1, f"Convert /{result.prefix} into a mask")
    detail(f"{full_octets} full octet(s) of 255" +
           (f", plus {remainder_bits} borrowed bit(s) in octet {idx}"
            if remainder_bits else " (no partial octet)"))
    detail(f"Mask = {_c(result.mask, GREEN)}")
    detail(f"IP   {_color_bits(result.binary_ip, result.prefix)}")
    detail(f"Mask {_color_bits(result.binary_mask, result.prefix)}")
    detail()

    # Step 2: magic number
    step(2, f"Magic number for octet {idx} (value {result.interesting_octet_value})")
    detail(f"Magic = 256 - {result.interesting_octet_value} = {_c(str(magic), GREEN)}")
    detail()

    if result.prefix >= 31:
        step(3, "Special case (/31 or /32)")
        if result.prefix == 31:
            detail("Point-to-point link (RFC 3021): no network/broadcast,")
            detail("both addresses are usable")
        else:
            detail("Host route: the only address is the host itself")
        detail()
        last_step = 4
    else:
        # Step 3: blocks around the host
        lower_block = (host_val // magic) * magic
        upper_block = lower_block + magic
        prev_block = lower_block - magic if lower_block - magic >= 0 else None

        block_list = [b for b in (prev_block, lower_block, upper_block) if b is not None]
        block_str = ", ".join(
            _c(str(b), GREEN, BOLD) if b == lower_block else str(b) for b in block_list
        ) + ", ..."
        step(3, f"List the blocks of {magic} in octet {idx}")
        detail(block_str)
        detail()

        step(4, f"Locate the host's octet {idx} value ({host_val})")
        detail(f"{lower_block} <= {host_val} < {upper_block}"
               f" -> falls in the block starting at {lower_block}")
        detail()

        step(5, "Subnet (network) address")
        detail(_c(result.network, GREEN))
        detail()

        step(6, "Broadcast address")
        detail(f"Broadcast = Subnet + Magic - 1 = "
               f"{lower_block} + {magic} - 1 = {upper_block - 1}")
        detail(_c(result.broadcast, GREEN))
        detail()
        last_step = 7

    step(last_step, "First / last valid host")
    detail(f"First = {_c(result.first_host, GREEN)}")
    detail(f"Last  = {_c(result.last_host, GREEN)}")
    detail()

    lines.append(f"{_c('[+]', GREEN, BOLD)} Usable hosts: {_c(str(result.usable_hosts), BOLD)} "
                 f"(out of {result.total_addresses} total addresses)")
    return "\n".join(lines)

# Output formatting

_TABLE_COLUMNS = [
    ("IP/CIDR", lambda r: f"{r.ip}/{r.prefix}"),
    ("Mask", lambda r: r.mask),
    ("Magic", lambda r: str(r.magic_number)),
    ("Subnet", lambda r: r.network),
    ("Broadcast", lambda r: r.broadcast),
    ("First Host", lambda r: r.first_host),
    ("Last Host", lambda r: r.last_host),
    ("Usable", lambda r: str(r.usable_hosts)),
]

def print_table(results: List[SubnetResult]) -> None:
    """Print a clean, aligned table for one or more results"""
    headers = [name for name, _ in _TABLE_COLUMNS]
    rows = [[getter(r) for _, getter in _TABLE_COLUMNS] for r in results]

    widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows))
        for i in range(len(headers))
    ]
    gap = "  "
    total_width = sum(widths) + len(gap) * (len(widths) - 1)
    # last column isn't padded so lines don't end in spaces
    pad = widths[:-1] + [0]

    # pad first, then color, so ANSI codes don't break the alignment
    print(" " + gap.join(_c(h.ljust(w), BOLD, CYAN) for h, w in zip(headers, pad)))
    print(" " + _c("─" * total_width, DIM))
    for row in rows:
        cells = [cell.ljust(w) for cell, w in zip(row, pad)]
        cells[0] = _c(cells[0], BOLD)
        print(" " + gap.join(cells))

# CLI

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subnetting.py",
        description="IPv4 subnet calculator using the Magic Number Method.",
        epilog=(
            "Examples:\n"
            " python subnetting.py 192.168.1.201/29\n"
            " python subnetting.py 10.0.5.50/28 203.0.113.90/27 --explain\n"
            " python subnetting.py 172.16.100.9/29 --json\n"
            " python subnetting.py -f targets.txt\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="One or more addresses in CIDR notation (e.g. 192.168.1.0/24)."
    )

    parser.add_argument(
        "-f", "--file",
        help="Path to a text file with one CIDR entry per line (# for comments)."
    )

    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output results as JSON instead of a table"
    )

    parser.add_argument(
        "-e", "--explain",
        action="store_true",
        help="Print step-by-step explanation using the magic number method"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    return parser

def _collect_targets(args: argparse.Namespace) -> List[str]:
    targets = list(args.targets)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    targets.append(line)
    return targets

def main(argv: Optional[List[str]] = None) -> int:
    global _COLOR

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # no colors when piping, when asked, or when NO_COLOR is set
    _COLOR = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ

    try:
        targets = _collect_targets(args)
    except OSError as exc:
        error(f"Can't read '{args.file}': {exc.strerror}")
        return 1
    except UnicodeDecodeError:
        error(f"Can't read '{args.file}': not a UTF-8 text file")
        return 1

    if not targets:
        parser.print_help()
        return 1

    results: List[SubnetResult] = []
    failed = 0
    for target in targets:
        try:
            ip_str, prefix = parse_cidr(target)
            results.append(calculate(ip_str, prefix))
        except ValueError as exc:
            error(str(exc))
            failed += 1

    # before the empty check so scripts always get a JSON array, even []
    if args.json:
        if args.explain:
            warn("--explain is ignored in JSON mode")
        print(json.dumps([r.as_dict() for r in results], indent=2))
        return 1 if failed else 0

    if not results:
        return 1

    info(f"{len(results)} subnet(s) calculated")
    print()
    print_table(results)

    if args.explain:
        for result in results:
            print()
            print(explain(result))

    if failed:
        print()
        warn(f"{failed} target(s) skipped because of errors")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
