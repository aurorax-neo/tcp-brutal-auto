#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(dirname -- "$SCRIPT_DIR")
OUTPUT=${1:-"$REPO_DIR/china-mainland-ipv4.txt"}
OUTPUT_PARENT=$(dirname -- "$OUTPUT")
mkdir -p "$OUTPUT_PARENT"
OUTPUT_DIR=$(CDPATH= cd -- "$OUTPUT_PARENT" && pwd)
OUTPUT="$OUTPUT_DIR/$(basename -- "$OUTPUT")"
APNIC_URL=${APNIC_URL:-"https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"}
BETT_RULES_URL=${BETT_RULES_URL:-"https://cdn.jsdelivr.net/gh/appshubcc/bett-rules@meta/geo-lite/geoip/cn.list"}

mkdir -p "$OUTPUT_DIR"
TMP_DIR=$(mktemp -d "$OUTPUT_DIR/.update-cn-ipv4.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

APNIC_RAW="$TMP_DIR/delegated-apnic-latest"
BETT_RULES_RAW="$TMP_DIR/bett-rules-cn.list"
GENERATED="$TMP_DIR/china-mainland-ipv4.txt"

curl --fail --silent --show-error --location --retry 3 \
  --connect-timeout 10 --max-time 120 \
  "$APNIC_URL" -o "$APNIC_RAW"
curl --fail --silent --show-error --location --retry 3 \
  --connect-timeout 10 --max-time 120 \
  "$BETT_RULES_URL" -o "$BETT_RULES_RAW"

python3 - "$APNIC_RAW" "$BETT_RULES_RAW" "$GENERATED" "$APNIC_URL" "$BETT_RULES_URL" <<'PY'
import ipaddress
import os
import sys
from datetime import datetime, timezone

apnic_path, bett_rules_path, output_path, apnic_url, bett_rules_url = sys.argv[1:]
apnic_networks = []
bett_rules_networks = []
apnic_record_count = 0

with open(apnic_path, encoding="ascii") as source:
    for raw_line in source:
        fields = raw_line.rstrip("\n").split("|")
        if len(fields) != 7:
            continue
        registry, country, resource_type, start, value, _, status = fields
        if (
            registry != "apnic"
            or country != "CN"
            or resource_type != "ipv4"
            or status not in {"allocated", "assigned"}
        ):
            continue

        first = ipaddress.IPv4Address(start)
        count = int(value)
        if count <= 0:
            raise ValueError(f"invalid address count: {raw_line.rstrip()}")
        last = ipaddress.IPv4Address(int(first) + count - 1)
        apnic_networks.extend(ipaddress.summarize_address_range(first, last))
        apnic_record_count += 1

if not apnic_networks:
    raise RuntimeError("APNIC data contains no CN IPv4 records")
if not 5_000 <= apnic_record_count <= 20_000:
    raise RuntimeError(f"unexpected APNIC CN record count: {apnic_record_count}")

with open(bett_rules_path, encoding="ascii") as source:
    for raw_line in source:
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        network = ipaddress.ip_network(line)
        if network.version != 4:
            continue
        if not network.is_global:
            raise ValueError(f"bett-rules contains non-public IPv4 network: {network}")
        bett_rules_networks.append(network)

if not bett_rules_networks:
    raise RuntimeError("bett-rules data contains no CN IPv4 networks")
if not 5_000 <= len(bett_rules_networks) <= 20_000:
    raise RuntimeError(f"unexpected bett-rules CN network count: {len(bett_rules_networks)}")

apnic_collapsed = list(ipaddress.collapse_addresses(apnic_networks))
bett_rules_collapsed = list(ipaddress.collapse_addresses(bett_rules_networks))
collapsed = list(ipaddress.collapse_addresses(apnic_collapsed + bett_rules_collapsed))
if any(not network.is_global for network in collapsed):
    raise RuntimeError("combined data contains non-public IPv4 networks")
apnic_addresses = sum(network.num_addresses for network in apnic_collapsed)
combined_addresses = sum(network.num_addresses for network in collapsed)
added_addresses = combined_addresses - apnic_addresses

if not 250_000_000 <= combined_addresses <= 500_000_000:
    raise RuntimeError(f"unexpected combined IPv4 address count: {combined_addresses}")
if not 5_000 <= len(collapsed) <= 20_000:
    raise RuntimeError(f"unexpected combined CIDR count: {len(collapsed)}")

if os.path.exists(output_path):
    previous_addresses = 0
    with open(output_path, encoding="ascii") as previous:
        for raw_line in previous:
            line = raw_line.split("#", 1)[0].strip()
            if line:
                previous_addresses += ipaddress.ip_network(line).num_addresses
    if previous_addresses and abs(combined_addresses - previous_addresses) > previous_addresses // 4:
        raise RuntimeError(
            f"combined address count changed by more than 25% "
            f"({previous_addresses} -> {combined_addresses})"
        )

generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

with open(output_path, "w", encoding="ascii", newline="\n") as output:
    output.write("# China mainland IPv4 CIDR ranges\n")
    output.write(f"# APNIC source: {apnic_url}\n")
    output.write(f"# GeoIP source: {bett_rules_url}\n")
    output.write("# Scope: union of APNIC CN allocations and bett-rules CN GeoIP\n")
    output.write(f"# Generated: {generated_at}\n")
    output.write(
        f"# APNIC records: {apnic_record_count}; "
        f"bett-rules IPv4 CIDRs: {len(bett_rules_collapsed)}; "
        f"combined CIDRs: {len(collapsed)}\n"
    )
    output.write(
        f"# Combined addresses: {combined_addresses}; "
        f"added beyond APNIC: {added_addresses}\n"
    )
    for network in collapsed:
        output.write(f"{network}\n")

print(
    f"generated {len(collapsed)} CIDRs; "
    f"APNIC records={apnic_record_count}, "
    f"bett-rules IPv4 CIDRs={len(bett_rules_collapsed)}, "
    f"addresses added beyond APNIC={added_addresses}"
)
PY

mkdir -p "$(dirname -- "$OUTPUT")"
mv "$GENERATED" "$OUTPUT"
printf 'wrote %s\n' "$OUTPUT"
