import ipaddress
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from subnetting import calculate, main, parse_cidr

SCRIPT = Path(__file__).resolve().parent.parent / "subnetting.py"

ADDRESSES = [
    "0.0.0.0",
    "0.0.0.1",
    "1.2.3.4",
    "10.0.5.50",
    "127.255.255.255",
    "128.0.0.0",
    "172.16.100.9",
    "192.168.1.102",
    "203.0.113.90",
    "224.0.0.251",
    "255.255.255.254",
    "255.255.255.255",
]


# differential against ipaddress

@pytest.mark.parametrize("prefix", range(33))
@pytest.mark.parametrize("address", ADDRESSES)
def test_matches_ipaddress_for_every_prefix(address, prefix):
    result = calculate(address, prefix)
    net = ipaddress.ip_network(f"{address}/{prefix}", strict=False)

    assert result.mask == str(net.netmask)
    assert result.wildcard == str(net.hostmask)
    assert result.network == str(net.network_address)
    assert result.broadcast == str(net.broadcast_address)
    assert result.total_addresses == net.num_addresses
    assert result.binary_mask.replace(".", "") == format(int(net.netmask), "032b")
    assert result.binary_ip.replace(".", "") == format(int(ipaddress.IPv4Address(address)), "032b")

    # /31 and /32 are checked in their own tests
    if prefix <= 30:
        assert result.first_host == str(net.network_address + 1)
        assert result.last_host == str(net.broadcast_address - 1)
        assert result.usable_hosts == net.num_addresses - 2


# /31 and /32

def test_slash_31_has_two_usable_hosts():
    result = calculate("10.0.0.1", 31)
    assert result.usable_hosts == 2
    assert result.total_addresses == 2
    assert result.network == result.first_host == "10.0.0.0"
    assert result.broadcast == result.last_host == "10.0.0.1"


def test_slash_31_hosts_match_ipaddress():
    net = ipaddress.ip_network("203.0.113.90/31")
    result = calculate("203.0.113.90", 31)
    assert [result.first_host, result.last_host] == [str(h) for h in net.hosts()]


def test_slash_32_is_a_single_host():
    result = calculate("192.168.1.7", 32)
    assert result.usable_hosts == 1
    assert result.total_addresses == 1
    assert result.network == result.broadcast == "192.168.1.7"
    assert result.first_host == result.last_host == "192.168.1.7"


def test_slash_32_at_the_top_of_the_address_space():
    result = calculate("255.255.255.255", 32)
    assert result.first_host == result.last_host == "255.255.255.255"


# magic number and interesting octet

@pytest.mark.parametrize(
    "prefix, octet_index, octet_value, magic",
    [
        (0, 1, 0, 256),
        (4, 1, 240, 16),
        (7, 1, 254, 2),
        (8, 2, 0, 256),
        (12, 2, 240, 16),
        (16, 3, 0, 256),
        (19, 3, 224, 32),
        (24, 4, 0, 256),
        (27, 4, 224, 32),
        (30, 4, 252, 4),
        (31, 4, 254, 2),
        (32, 4, 255, 1),
    ],
)
def test_magic_number_and_interesting_octet(prefix, octet_index, octet_value, magic):
    result = calculate("10.20.30.40", prefix)
    assert result.interesting_octet_index == octet_index
    assert result.interesting_octet_value == octet_value
    assert result.magic_number == magic


@pytest.mark.parametrize("prefix", range(32))
def test_network_is_a_multiple_of_the_magic_number(prefix):
    result = calculate("172.16.100.9", prefix)
    octet = int(result.network.split(".")[result.interesting_octet_index - 1])
    assert octet % result.magic_number == 0


# parse_cidr

def test_parse_cidr_splits_address_and_prefix():
    assert parse_cidr(" 192.168.1.102/27 ") == ("192.168.1.102", 27)


@pytest.mark.parametrize(
    "bad",
    [
        "192.168.1.1",
        "192.168.1.1/33",
        "192.168.1.1/-1",
        "192.168.1.1/abc",
        "192.168.1.1/",
        "192.168.1.1/²",
        "192.168.1.1/٢٤",
        "192.168.1.256/24",
        "10.0.0/8",
        "not.an.ip.addr/24",
        "/24",
    ],
)
def test_parse_cidr_rejects_malformed_input(bad):
    with pytest.raises(ValueError):
        parse_cidr(bad)


# main()

def test_main_returns_0_when_every_target_succeeds(capsys):
    assert main(["192.168.1.201/29", "10.0.5.50/28"]) == 0
    assert "192.168.1.200" in capsys.readouterr().out


def test_main_returns_1_when_any_target_fails(capsys):
    assert main(["192.168.1.201/29", "10.0.0.1/33"]) == 1
    captured = capsys.readouterr()
    assert "192.168.1.200" in captured.out
    assert "/33" in captured.err


def test_main_returns_1_when_every_target_fails(capsys):
    assert main(["nope/24"]) == 1


def test_main_returns_1_with_no_targets(capsys):
    assert main([]) == 1


def test_main_reads_targets_from_a_file(tmp_path, capsys):
    targets = tmp_path / "targets.txt"
    targets.write_text("# lab\n192.168.1.201/29\n\n10.0.5.50/28  # office\n")
    assert main(["-f", str(targets)]) == 0
    assert "2 subnet(s) calculated" in capsys.readouterr().out


def test_main_returns_1_when_the_file_is_missing(tmp_path, capsys):
    assert main(["-f", str(tmp_path / "missing.txt")]) == 1


def test_main_returns_1_when_the_file_is_not_utf8(tmp_path, capsys):
    targets = tmp_path / "targets.bin"
    targets.write_bytes(b"\xff\xfe\x00\x01\n")
    assert main(["-f", str(targets)]) == 1
    assert "not a UTF-8 text file" in capsys.readouterr().err


def test_warnings_come_after_the_table_when_redirected():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "10.0.0.1/33", "192.168.1.1/24"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    out = proc.stdout
    assert out.index("/33") < out.index("subnet(s) calculated")
    assert out.index("192.168.1.254") < out.index("skipped")


# output formats

def test_json_output_parses_and_has_the_expected_keys(capsys):
    assert main(["--json", "172.16.100.9/29", "10.0.0.1/31"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2
    assert set(data[0]) == {
        "ip", "prefix", "mask", "wildcard", "network", "broadcast",
        "first_host", "last_host", "usable_hosts", "total_addresses",
        "binary_ip", "binary_mask", "interesting_octet_index",
        "interesting_octet_value", "magic_number",
    }
    assert data[0]["network"] == "172.16.100.8"
    assert data[1]["usable_hosts"] == 2


def test_json_output_stays_valid_when_a_target_fails(capsys):
    assert main(["--json", "172.16.100.9/29", "bad"]) == 1
    assert len(json.loads(capsys.readouterr().out)) == 1


def test_json_output_is_an_empty_list_when_every_target_fails(capsys):
    assert main(["--json", "bad", "10.0.0.1/33"]) == 1
    assert json.loads(capsys.readouterr().out) == []


def _run_in_tty(*args):
    # color only turns on when stdout is a real terminal, so give it one.
    # imported here because pty fails to import on windows
    import pty

    main_fd, child_fd = pty.openpty()
    env = {k: v for k, v in os.environ.items() if k != "NO_COLOR"}
    proc = subprocess.Popen(
        [sys.executable, str(SCRIPT), *args],
        stdout=child_fd, stderr=child_fd, env=env,
    )
    os.close(child_fd)
    chunks = []
    while True:
        try:
            chunk = os.read(main_fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    os.close(main_fd)
    proc.wait()
    return b"".join(chunks).decode()


@pytest.mark.skipif(sys.platform == "win32", reason="pty is unix only")
def test_tty_output_is_colored_by_default():
    assert "\033[" in _run_in_tty("192.168.1.102/27", "--explain")


@pytest.mark.skipif(sys.platform == "win32", reason="pty is unix only")
def test_no_color_output_has_no_ansi_escapes():
    assert "\033[" not in _run_in_tty("192.168.1.102/27", "--explain", "--no-color")
