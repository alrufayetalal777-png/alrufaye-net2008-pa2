# Student: [Enter your name] | Student ID: 101344712
"""NET2008 PA2: audit network inventory against a YAML policy."""

import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import yaml


class InputError(Exception):
    """An input file could not be read or parsed."""


class Device:
    """An inventory device with methods for interface counting and policy checking."""

    def __init__(self, element):
        """Read device details from one XML element."""
        self.id = element.get("id")
        self.role = element.get("role", "")
        self.os = element.get("os", "")
        self.owner = (element.findtext("owner") or "").strip()
        self.statuses = [item.get("status", "") for item in element.findall("interface")]

    def interface_counts(self):
        """Count up, down and all other interface states."""
        counts = {"up": 0, "down": 0, "other": 0}
        for status in self.statuses:
            counts[status if status in ("up", "down") else "other"] += 1
        return counts

    def violations(self, policy):
        """Return every enabled policy violation for this device."""
        problems = []
        if "min_os" in policy:
            allowed = policy["min_os"]
            if self.role not in allowed:
                problems.append({"device": self.id, "type": "unknown_role", "role": self.role})
            elif version_parts(self.os) < version_parts(str(allowed[self.role])):
                problems.append({"device": self.id, "type": "os_outdated", "found": self.os, "required": str(allowed[self.role])})
        if policy.get("require_owner") is True and not self.owner:
            problems.append({"device": self.id, "type": "missing_owner"})
        if "max_down_interfaces" in policy:
            down = self.interface_counts()["down"]
            if down > policy["max_down_interfaces"]:
                problems.append({"device": self.id, "type": "too_many_down", "down": down})
        return problems


def version_parts(version):
    """Compare dotted numeric versions with trailing zeros treated as equal."""
    parts = [int(part) for part in version.split(".")]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def read_inventory(filename):
    """Load XML and raise InputError with the filename on failure."""
    try:
        with Path(filename).open("rb") as file:
            root = ET.parse(file).getroot()
        return root
    except (OSError, ET.ParseError) as error:
        raise InputError(f"{filename}: {error}") from error


def read_policy(filename):
    """Safely load a YAML mapping, allowing an empty file."""
    try:
        with Path(filename).open("r", encoding="utf-8") as file:
            policy = yaml.safe_load(file)
    except (OSError, yaml.YAMLError, UnicodeError) as error:
        raise InputError(f"{filename}: {error}") from error
    if policy is None:
        return {}
    if not isinstance(policy, dict):
        raise InputError(f"{filename}: policy must be a YAML mapping")
    return policy


def audit(root, policy):
    """Build the full report, skipping devices without an id."""
    report = {"site": root.get("site"), "total_devices": 0, "skipped_devices": 0,
              "roles": {}, "interfaces": {"up": 0, "down": 0, "other": 0},
              "violations": [], "compliant": []}
    roles = Counter()
    for element in root.findall("device"):
        device = Device(element)
        if device.id is None:
            report["skipped_devices"] += 1
            continue
        report["total_devices"] += 1
        roles[device.role] += 1
        for state, count in device.interface_counts().items():
            report["interfaces"][state] += count
        issues = device.violations(policy)
        report["violations"].extend(issues)
        if not issues:
            report["compliant"].append(device.id)
    report["roles"] = dict(roles)
    report["compliant"].sort()
    return report


def main(argv=None):
    """Run the CLI; 0 = success, 1 = invalid input, 2 = usage error."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml", file=sys.stderr)
        return 2
    try:
        root = read_inventory(args[0])
        policy = read_policy(args[1])
        report = audit(root, policy)
        with Path("audit.json").open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
            file.write("\n")
    except InputError as error:
        print(error, file=sys.stderr)
        return 1
    print(f"Audited {report['total_devices']} devices; {len(report['violations'])} violations. Wrote audit.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
