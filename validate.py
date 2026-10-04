#!/usr/bin/env python3
"""
validate.py — Sigma rule pack validator.

Loads every rule under rules/ and checks:
  * required Sigma fields (title, logsource, detection, falsepositives, level)
  * id is a valid UUID (when present)
  * ATT&CK tags match attack.tXXXX[.XXX] format
  * level and status use allowed Sigma values
  * detection block contains a condition

Requires PyYAML. If it is not installed, prints a graceful message and exits.
Usage: python3 validate.py [--rules-dir rules]
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is not installed — cannot parse YAML rules.")
    print("Install it with: pip install pyyaml")
    sys.exit(2)

REQUIRED_FIELDS = ["title", "logsource", "detection", "falsepositives", "level"]
ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
ALLOWED_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
ATTCK_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
ATTCK_TACTIC_RE = re.compile(r"^attack\.[a-z_]+$")


def validate_rule(path: Path):
    """Return a list of error strings for one rule file (empty = pass)."""
    errors = []
    try:
        with open(path) as fh:
            rule = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]

    if not isinstance(rule, dict):
        return ["top-level document is not a mapping"]

    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"missing required field: {field}")

    rule_id = rule.get("id")
    if rule_id is not None and not UUID_RE.match(str(rule_id)):
        errors.append(f"id is not a valid UUID: {rule_id}")

    level = rule.get("level")
    if level is not None and str(level).lower() not in ALLOWED_LEVELS:
        errors.append(f"invalid level: {level}")

    status = rule.get("status")
    if status is not None and str(status).lower() not in ALLOWED_STATUSES:
        errors.append(f"invalid status: {status}")

    detection = rule.get("detection")
    if isinstance(detection, dict) and "condition" not in detection:
        errors.append("detection block has no condition")

    logsource = rule.get("logsource")
    if isinstance(logsource, dict) and not any(
        k in logsource for k in ("category", "product", "service", "definition")
    ):
        errors.append("logsource has none of category/product/service/definition")

    for tag in rule.get("tags", []) or []:
        tag = str(tag)
        if tag.startswith("attack.t"):
            if not ATTCK_TAG_RE.match(tag):
                errors.append(f"malformed ATT&CK technique tag: {tag}")
        elif tag.startswith("attack."):
            if not ATTCK_TACTIC_RE.match(tag):
                errors.append(f"malformed ATT&CK tactic tag: {tag}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Sigma rule pack.")
    parser.add_argument("--rules-dir", default="rules",
                        help="directory containing rule YAML files")
    args = parser.parse_args()

    rules_dir = Path(args.rules_dir)
    files = sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml"))
    if not files:
        print(f"No rule files found under {rules_dir}")
        return 1

    failed = 0
    for path in files:
        rel = path.relative_to(Path.cwd()) if path.is_absolute() else path
        errors = validate_rule(path)
        if errors:
            failed += 1
            print(f"FAIL  {rel}")
            for err in errors:
                print(f"       - {err}")
        else:
            print(f"PASS  {rel}")

    print(f"\n{len(files) - failed}/{len(files)} rules passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
