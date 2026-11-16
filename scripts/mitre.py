#!/usr/bin/env python3
"""Write internal/mitre/catalogue.json from the two upstream files.

    scripts/mitre.py enterprise-attack.json ATLAS.yaml > internal/mitre/catalogue.json

The first is the ATT&CK enterprise STIX bundle of mitre-attack/attack-stix-data,
the second a v6 ATLAS file of mitre-atlas/atlas-data. It needs PyYAML.
"""
import json
import re
import sys

import yaml


def first_sentence(text):
    """Return the opening sentence of a description, on one line and without links."""
    text = " ".join(re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text or "").split())
    match = re.match(r"(.+?[.!?])(?:\s|$)", text)
    return match.group(1) if match else text


def external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def live(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def attack(path):
    with open(path, encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]
    version = next(o["x_mitre_version"] for o in objects if o["type"] == "x-mitre-collection")
    by_ref = {o["id"]: o for o in objects}
    tactics = {external_id(o): o["name"] for o in objects if o["type"] == "x-mitre-tactic" and live(o)}
    by_phase = {o["x_mitre_shortname"]: external_id(o) for o in objects if o["type"] == "x-mitre-tactic" and live(o)}
    mitigations = {
        external_id(o): {"name": o["name"], "summary": first_sentence(o.get("description"))}
        for o in objects
        if o["type"] == "course-of-action" and live(o) and external_id(o).startswith("M")
    }
    techniques = {
        external_id(o): {
            "name": o["name"],
            "tactics": [by_phase[p["phase_name"]] for p in o.get("kill_chain_phases", []) if p["phase_name"] in by_phase],
            "mitigations": [],
        }
        for o in objects
        if o["type"] == "attack-pattern" and live(o)
    }
    for rel in objects:
        if rel["type"] != "relationship" or rel.get("relationship_type") != "mitigates" or not live(rel):
            continue
        source, target = by_ref.get(rel["source_ref"]), by_ref.get(rel["target_ref"])
        if not source or not target or not live(source) or not live(target):
            continue
        mitigation, technique = external_id(source), external_id(target)
        if mitigation in mitigations and technique in techniques:
            techniques[technique]["mitigations"].append(mitigation)
    return {"version": version, "tactics": tactics, "mitigations": mitigations, "techniques": techniques}


def atlas(path):
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    techniques = {}
    for ident, entry in data["techniques"].items():
        techniques[ident] = {"name": entry["name"], "tactics": [], "mitigations": []}
        reference = entry.get("attack-reference") or {}
        if reference.get("id"):
            techniques[ident]["attack"] = reference["id"]
    for links in data["relationships"].values():
        for link in links.get("achieves", []):
            if link["source"] in techniques and link["target"] in data["tactics"]:
                techniques[link["source"]]["tactics"].append(link["target"])
        for link in links.get("mitigates", []):
            if link["target"] in techniques and link["source"] in data["mitigations"]:
                techniques[link["target"]]["mitigations"].append(link["source"])
    return {
        "version": str(data["collection"]["version"]),
        "tactics": {ident: entry["name"] for ident, entry in data["tactics"].items()},
        "mitigations": {
            ident: {"name": entry["name"], "summary": first_sentence(entry.get("description"))}
            for ident, entry in data["mitigations"].items()
        },
        "techniques": techniques,
    }


def write(out, name, framework, last):
    out.write('  %s: {\n    "version": %s,\n' % (json.dumps(name), json.dumps(framework["version"])))
    for key in ("tactics", "mitigations"):
        out.write("    %s: {\n" % json.dumps(key))
        items = sorted(framework[key].items())
        for i, (ident, label) in enumerate(items):
            text = json.dumps(label, ensure_ascii=False)
            out.write("      %s: %s%s\n" % (json.dumps(ident), text, "," if i < len(items) - 1 else ""))
        out.write("    },\n")
    out.write('    "techniques": {\n')
    items = sorted(framework["techniques"].items())
    for i, (ident, entry) in enumerate(items):
        entry["tactics"] = sorted(set(entry["tactics"]))
        entry["mitigations"] = sorted(set(entry["mitigations"]))
        ordered = {key: entry[key] for key in ("name", "attack", "tactics", "mitigations") if key in entry}
        out.write("      %s: %s%s\n" % (json.dumps(ident), json.dumps(ordered), "," if i < len(items) - 1 else ""))
    out.write("    }\n  }%s\n" % ("" if last else ","))


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    out = sys.stdout
    out.write("{\n")
    write(out, "attack", attack(sys.argv[1]), False)
    write(out, "atlas", atlas(sys.argv[2]), True)
    out.write("}\n")


if __name__ == "__main__":
    main()
