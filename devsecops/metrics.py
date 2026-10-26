#!/usr/bin/env python3
"""Normaliza los informes de los 7 controles del pipeline DevSecOps del TFM (Online Boutique).

Lee los artefactos descargados del run (un subdirectorio por artefacto) y genera:
  - metrics.json  -> conteos por control y severidad (Critical/High/Medium/Low/Info)
  - metrics.md    -> tabla Markdown (se vuelca al resumen del run)

Criterios de normalización de severidad (documentados en la memoria, cap. 5.4):
  - Semgrep (JSON): ERROR/HIGH -> High, WARNING/MEDIUM -> Medium, INFO/LOW -> Low (SARIF como respaldo).
  - Trivy (fs / image): severidad nativa (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN->Info). En imagen se
    agregan los 10 servicios; una misma CVE en dos imágenes cuenta dos veces (son dos artefactos).
  - Gitleaks: todo secreto expuesto se considera High.
  - Checkov: sin severidad en la versión open source -> todo check fallido se considera High.
  - OWASP ZAP: riskcode 3 High, 2 Medium, 1 Low, 0 Info (se cuentan tipos de alerta).
  - Kyverno (admisión): cada par (política, workload) con resultado "fail" en los PolicyReports;
    severidad declarada por el resultado o, si no la tiene, High.

Uso: python metrics.py <dir_artefactos> [<dir_salida>]
"""
import json
import sys
from collections import Counter
from pathlib import Path

SEVS = ["Critical", "High", "Medium", "Low", "Info"]


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def norm(s):
    s = (s or "").strip().lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium",
            "low": "Low"}.get(s, "Info")


def semgrep(d):
    js = load(d / "sast-semgrep" / "semgrep.json")
    if js is not None:
        # Informe JSON nativo: incluye la severidad de la regla (ERROR/WARNING/INFO)
        lvl = {"CRITICAL": "Critical", "ERROR": "High", "HIGH": "High", "WARNING": "Medium",
               "MEDIUM": "Medium", "INFO": "Low", "LOW": "Low"}
        c, items = Counter(), []
        for r in js.get("results", []):
            sev = lvl.get(r.get("extra", {}).get("severity", ""), "Info")
            c[sev] += 1
            items.append({"rule": r.get("check_id"), "sev": sev, "file": r.get("path"),
                          "line": r.get("start", {}).get("line"),
                          "cwe": r.get("extra", {}).get("metadata", {}).get("cwe")})
        return c, items
    data = load(d / "sast-semgrep" / "semgrep.sarif")
    if data is None:
        return None, []
    c, items = Counter(), []
    lvl = {"error": "High", "warning": "Medium", "note": "Low"}
    for run in data.get("runs", []):
        for r in run.get("results", []):
            sev = lvl.get(r.get("level", "warning"), "Info")
            c[sev] += 1
            loc = r.get("locations", [{}])[0].get("physicalLocation", {})
            items.append({"rule": r.get("ruleId"), "sev": sev,
                          "file": loc.get("artifactLocation", {}).get("uri"),
                          "line": loc.get("region", {}).get("startLine")})
    return c, items


def trivy(path):
    data = load(path)
    if data is None:
        return None, []
    c, items, seen = Counter(), [], set()
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            key = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
            if key in seen:
                continue
            seen.add(key)
            sev = norm(v.get("Severity"))
            c[sev] += 1
            items.append({"id": v.get("VulnerabilityID"), "pkg": v.get("PkgName"),
                          "ver": v.get("InstalledVersion"), "fixed": v.get("FixedVersion"),
                          "sev": sev, "target": res.get("Target")})
    return c, items


def images(d):
    dirs = sorted(d.glob("container-*"))
    if not dirs:
        return None, []
    c, items = Counter(), []
    for sd in dirs:
        ci, it = trivy(sd / "trivy-image.json")
        if ci is None:
            continue
        svc = sd.name.removeprefix("container-")
        c.update(ci)
        items += [dict(i, svc=svc) for i in it]
    return c, items


def workload(res):
    # Pod "frontend-7d9f8c-x2k4p" -> "frontend"; Deployment/ReplicaSet conservan (casi) su nombre
    name, kind = res.get("name", ""), res.get("kind", "")
    parts = name.split("-")
    if kind == "Pod" and len(parts) > 2:
        return "-".join(parts[:-2])
    if kind == "ReplicaSet" and len(parts) > 1:
        return "-".join(parts[:-1])
    return name


def kyverno(d):
    data = load(d / "admission-kyverno" / "policyreports.json")
    if data is None:
        return None, []
    seen, c, items = {}, Counter(), []
    for rep in data.get("items", []) or []:
        scope = rep.get("scope") or {}
        for r in rep.get("results", []) or []:
            if r.get("result") != "fail":
                continue
            res = scope or (r.get("resources") or [{}])[0]
            key = (r.get("policy"), (r.get("rule") or "").removeprefix("autogen-"), workload(res))
            if key in seen:
                continue
            sev = norm(r.get("severity")) if r.get("severity") else "High"
            seen[key] = sev
            c[sev] += 1
            items.append({"policy": key[0], "rule": key[1], "workload": key[2], "sev": sev,
                          "message": (r.get("message") or "")[:300]})
    return c, items


def supply_chain(d):
    p = d / "admission-kyverno" / "supply-chain.txt"
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    out = {}
    for ln in filter(None, (x.strip() for x in lines)):
        svc, *kv = ln.split()
        out[svc] = dict(x.split("=", 1) for x in kv)
    return out


def gitleaks(d):
    data = load(d / "secrets-gitleaks" / "gitleaks.json")
    if data is None:
        return None, []
    c = Counter({"High": len(data)})
    items = [{"rule": f.get("RuleID"), "file": f.get("File"), "line": f.get("StartLine"),
              "sev": "High"} for f in data]
    return c, items


def checkov(d):
    data = load(d / "iac-checkov" / "checkov.json")
    if data is None:
        return None, []
    blocks = data if isinstance(data, list) else [data]
    c, items = Counter(), []
    for b in blocks:
        for f in b.get("results", {}).get("failed_checks", []) or []:
            sev = norm(f.get("severity")) if f.get("severity") else "High"
            c[sev] += 1
            items.append({"id": f.get("check_id"), "name": f.get("check_name"),
                          "resource": f.get("resource"), "file": f.get("file_path"), "sev": sev})
    return c, items


def zap(d):
    data = load(d / "dast-zap" / "report.json")
    if data is None:
        return None, []
    rc = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
    c, items = Counter(), []
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            sev = rc.get(str(a.get("riskcode")), "Info")
            c[sev] += 1
            items.append({"id": a.get("pluginid"), "name": a.get("alert"), "sev": sev,
                          "cwe": a.get("cweid"), "instances": int(a.get("count", 0) or 0)})
    return c, items


def main():
    art = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(".")
    out.mkdir(parents=True, exist_ok=True)
    controls = [
        ("SAST", "Semgrep", semgrep(art), True),
        ("SCA", "Trivy fs", trivy(art / "sca-reports" / "trivy-fs.json"), True),
        ("Secretos", "Gitleaks", gitleaks(art), True),
        ("Contenedor", "Trivy image (10 imágenes)", images(art), True),
        ("IaC", "Checkov", checkov(art), True),
        ("DAST", "OWASP ZAP", zap(art), True),
        ("Admisión", "Kyverno", kyverno(art), True),
    ]
    result, total = {"controls": []}, Counter()
    lines = ["| Control | Herramienta | " + " | ".join(SEVS) + " | Total |",
             "|---|---|" + "---|" * (len(SEVS) + 1)]
    for name, tool, (c, items), in_total in controls:
        if c is None:
            lines.append(f"| {name} | {tool} | " + " | ".join(["n/d"] * len(SEVS)) + " | n/d |")
            result["controls"].append({"control": name, "tool": tool, "available": False})
            continue
        row = {s: c.get(s, 0) for s in SEVS}
        tot = sum(row.values())
        if in_total:
            total.update(row)
        lines.append(f"| {name} | {tool} | " + " | ".join(str(row[s]) for s in SEVS) + f" | {tot} |")
        result["controls"].append({"control": name, "tool": tool, "available": True,
                                   "in_total": in_total, "by_severity": row, "total": tot,
                                   "items": items})
    trow = {s: total.get(s, 0) for s in SEVS}
    lines.append("| **TOTAL** | | " + " | ".join(f"**{trow[s]}**" for s in SEVS)
                 + f" | **{sum(trow.values())}** |")
    result["total"] = {"by_severity": trow, "total": sum(trow.values())}
    sc = supply_chain(art)
    if sc is not None:
        result["supply_chain"] = sc
        ok = {k: sum(1 for v in sc.values() if v.get(k) == "ok") for k in ("firma", "sbom", "provenance")}
        lines += ["", f"Cadena de suministro ({len(sc)} imágenes verificadas antes de desplegar): "
                  + ", ".join(f"{k} {v}/{len(sc)}" for k, v in ok.items())]
    neg = load(art / "admission-kyverno" / "negative-tests.json")
    if neg is not None:
        result["negative_tests"] = neg
        lines += ["", "Pruebas negativas de admisión: "
                  + ", ".join(f"{k} = {v}" for k, v in neg.items())]
    (out / "metrics.json").write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    (out / "metrics.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
