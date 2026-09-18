# subnet-calculator

[![tests](https://github.com/nytrek/subnet-calculator/actions/workflows/tests.yml/badge.svg)](https://github.com/nytrek/subnet-calculator/actions/workflows/tests.yml)

IPv4 subnet calculator for the command line. Give it an address in CIDR
notation and it prints the mask, network, broadcast, host range and usable
host count. With `--explain` it walks through the same steps you'd use to
solve it by hand with the magic number method.

## Requirements

Python 3.9 or newer. Standard library only, nothing to install.

## Usage

```
git clone https://github.com/nytrek/subnet-calculator.git
cd subnet-calculator
python3 subnetting.py 192.168.1.201/29
```

One or more targets:

```
$ python3 subnetting.py 10.0.5.50/28 203.0.113.90/27
[*] 2 subnet(s) calculated

 IP/CIDR          Mask             Magic  Subnet        Broadcast     First Host    Last Host     Usable
 ───────────────────────────────────────────────────────────────────────────────────────────────────────
 10.0.5.50/28     255.255.255.240  16     10.0.5.48     10.0.5.63     10.0.5.49     10.0.5.62     14
 203.0.113.90/27  255.255.255.224  32     203.0.113.64  203.0.113.95  203.0.113.65  203.0.113.94  30
```

Step-by-step walkthrough (table omitted):

```
$ python3 subnetting.py 192.168.1.102/27 --explain
[*] Walkthrough for 192.168.1.102/27
────────────────────────────────────────────────────────────
[1] Convert /27 into a mask
    3 full octet(s) of 255, plus 3 borrowed bit(s) in octet 4
    Mask = 255.255.255.224
    IP   11000000.10101000.00000001.01100110
    Mask 11111111.11111111.11111111.11100000

[2] Magic number for octet 4 (value 224)
    Magic = 256 - 224 = 32

[3] List the blocks of 32 in octet 4
    64, 96, 128, ...

[4] Locate the host's octet 4 value (102)
    96 <= 102 < 128 -> falls in the block starting at 96

[5] Subnet (network) address
    192.168.1.96

[6] Broadcast address
    Broadcast = Subnet + Magic - 1 = 96 + 32 - 1 = 127
    192.168.1.127

[7] First / last valid host
    First = 192.168.1.97
    Last  = 192.168.1.126

[+] Usable hosts: 30 (out of 32 total addresses)
```

Bad targets are reported and skipped, and the exit code is 1 if any failed:

```
$ python3 subnetting.py 10.0.0.1/33 192.168.1.1/24
[-] Prefix /33 is out of range. Must be between /0 and /32
[*] 1 subnet(s) calculated

 IP/CIDR         Mask           Magic  Subnet       Broadcast      First Host   Last Host      Usable
 ────────────────────────────────────────────────────────────────────────────────────────────────────
 192.168.1.1/24  255.255.255.0  256    192.168.1.0  192.168.1.255  192.168.1.1  192.168.1.254  254

[!] 1 target(s) skipped because of errors
```

`/31` is treated as a point-to-point link (RFC 3021, two usable hosts) and
`/32` as a host route (one).

## The magic number method

1. Find the interesting octet: the first octet of the mask that isn't 255.
2. Magic number = 256 minus that octet's mask value. For a /27 the mask is
   255.255.255.224, so the magic number is 32.
3. Subnets start at multiples of the magic number in that octet: 0, 32, 64,
   96, 128...
4. The block the host falls into is its subnet. The broadcast is the next
   block minus one, and the usable hosts are everything in between.

## Options

| Option            | Description                                          |
|-------------------|------------------------------------------------------|
| `targets`         | One or more addresses in CIDR notation               |
| `-f`, `--file`    | Read targets from a file, one per line, `#` comments |
| `-j`, `--json`    | Output results as JSON instead of a table            |
| `-e`, `--explain` | Print the step-by-step walkthrough for each target   |
| `--no-color`      | Disable colored output                               |

Color is also off when stdout isn't a terminal or `NO_COLOR` is set.

## Running the tests

```
pip install pytest
pytest
```

## License

MIT, see [LICENSE](LICENSE).
