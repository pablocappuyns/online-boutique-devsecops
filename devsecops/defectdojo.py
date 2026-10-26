#!/usr/bin/env python3
"""Importa los informes del pipeline en DefectDojo y extrae métricas (OE5).

Uso: python defectdojo.py <dir_artefactos> <etiqueta> <dir_salida>
Variables de entorno: DD_URL, DD_USER, DD_PASS.

- Crea (si no existe) el producto "Online Boutique" y un engagement por etiqueta
  (p. ej. "baseline" o "remediado").
- Importa cada informe con su parser nativo de DefectDojo (un test por imagen) y las
  violaciones de Kyverno como Generic Findings Import.
- Aplica el triaje manual de devsecops/triage.json (falsos positivos documentados).
- Exporta dd_metrics.json con conteos por severidad, herramienta, CWE y
  categoría OWASP Top 10:2021, además de duplicados y falsos positivos.
"""
import json
import os
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import requests

URL = os.environ.get("DD_URL", "http://localhost:8080").rstrip("/")
PRODUCT = "Online Boutique"

# Informe -> parser de DefectDojo
REPORTS = [
    ("sast-semgrep/semgrep.json", "Semgrep JSON Report", "Semgrep (SAST)"),
    ("sca-reports/trivy-fs.json", "Trivy Scan", "Trivy fs (SCA)"),
    ("secrets-gitleaks/gitleaks.json", "Gitleaks Scan", "Gitleaks (secretos)"),
    ("iac-checkov/checkov-merged.json", "Checkov Scan", "Checkov (IaC)"),
    ("dast-zap/report.xml", "ZAP Scan", "OWASP ZAP (DAST)"),
]

# CWE -> OWASP Top 10:2021 (lista oficial de CWE por categoría, subconjunto relevante)
OWASP_2021 = {
    "A01 Broken Access Control": [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359,
                                  377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651,
                                  668, 706, 862, 863, 913, 922, 1275],
    "A02 Cryptographic Failures": [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329,
                                   330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760,
                                   780, 818, 916],
    "A03 Injection": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99,
                      113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917, 1333, 1336],
    "A04 Insecure Design": [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419,
                            430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646,
                            650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
    "A05 Security Misconfiguration": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614,
                                      693, 756, 776, 942, 1004, 1032, 1174, 1336, 829, 1021, 525],
    "A06 Vulnerable and Outdated Components": [937, 1035, 1104],
    "A07 Identification and Authentication Failures": [255, 259, 287, 288, 290, 294, 295, 297, 300,
                                                       302, 304, 306, 307, 346, 384, 521, 613, 620,
                                                       640, 798, 940, 1216],
    "A08 Software and Data Integrity Failures": [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    "A09 Security Logging and Monitoring Failures": [117, 223, 532, 778],
    "A10 Server-Side Request Forgery": [918],
}
CWE2OWASP = {}
for cat, cwes in OWASP_2021.items():
    for c in cwes:
        CWE2OWASP.setdefault(c, cat)


def kyverno_generic(art):
    """PolicyReports (resultados fail) -> formato Generic Findings Import de DefectDojo."""
    p = art / "admission-kyverno" / "policyreports.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    seen, out = set(), []
    for rep in data.get("items", []) or []:
        res = rep.get("scope") or {}
        name, kind = res.get("name", ""), res.get("kind", "")
        parts = name.split("-")
        wl = "-".join(parts[:-2]) if kind == "Pod" and len(parts) > 2 else (
            "-".join(parts[:-1]) if kind == "ReplicaSet" and len(parts) > 1 else name)
        for r in rep.get("results", []) or []:
            if r.get("result") != "fail":
                continue
            rule = (r.get("rule") or "").removeprefix("autogen-")
            key = (r.get("policy"), rule, wl)
            if key in seen:
                continue
            seen.add(key)
            integ = r.get("policy") in ("verify-image-signatures", "require-image-digest")
            out.append({"title": f"Kyverno {r.get('policy')}: {wl}", "severity": "High",
                        "description": r.get("message") or "", "component_name": wl,
                        "cwe": 494 if integ else 250, "unique_id_from_tool": "|".join(key),
                        "mitigation": "Ajustar el manifiesto o la imagen a la política de admisión"})
    return {"findings": out}


class DD:
    def __init__(self):
        self.s = requests.Session()

    def wait(self, timeout=900):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                if self.s.get(f"{URL}/login", timeout=5).status_code == 200:
                    return
            except requests.RequestException:
                pass
            time.sleep(10)
        raise SystemExit("DefectDojo no responde")

    def login(self):
        r = self.s.post(f"{URL}/api/v2/api-token-auth/",
                        data={"username": os.environ["DD_USER"], "password": os.environ["DD_PASS"]})
        r.raise_for_status()
        self.s.headers["Authorization"] = f"Token {r.json()['token']}"

    def get_all(self, path, **params):
        params.setdefault("limit", 500)
        url, out = f"{URL}/api/v2/{path}/", []
        while url:
            r = self.s.get(url, params=params)
            r.raise_for_status()
            j = r.json()
            out += j["results"]
            url, params = j.get("next"), None
        return out


def main():
    art, label, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    dd = DD()
    dd.wait()
    dd.login()
    # Deduplicación activada antes de importar (desactivada por defecto en la instalación)
    r = dd.s.patch(f"{URL}/api/v2/system_settings/1/", json={"enable_deduplication": True})
    print(f"[config] deduplicación: HTTP {r.status_code}")

    # Checkov con varios -d escribe documentos JSON concatenados: el parser de DefectDojo espera
    # un único documento (objeto o lista)
    ck = art / "iac-checkov" / "checkov.json"
    if ck.exists():
        dec, txt, pos, docs = json.JSONDecoder(), ck.read_text(encoding="utf-8"), 0, []
        while pos < len(txt):
            while pos < len(txt) and txt[pos].isspace():
                pos += 1
            if pos >= len(txt):
                break
            obj, pos = dec.raw_decode(txt, pos)
            docs += obj if isinstance(obj, list) else [obj]
        (art / "iac-checkov" / "checkov-merged.json").write_text(json.dumps(docs), encoding="utf-8")
    reports = list(REPORTS)
    for d in sorted(art.glob("container-*")):
        svc = d.name.removeprefix("container-")
        reports.append((f"{d.name}/trivy-image.json", "Trivy Scan", f"Trivy image ({svc})"))
    gen = kyverno_generic(art)
    if gen is not None:
        (art / "kyverno-generic.json").write_text(json.dumps(gen, ensure_ascii=False), encoding="utf-8")
        reports.append(("kyverno-generic.json", "Generic Findings Import", "Kyverno (admisión)"))
    imported = []
    for rel, scan_type, title in reports:
        f = art / rel
        if not f.exists():
            print(f"[omitido] {rel} no existe")
            continue
        with open(f, "rb") as fh:
            r = dd.s.post(f"{URL}/api/v2/import-scan/", files={"file": fh}, data={
                "scan_type": scan_type, "test_title": title, "product_name": PRODUCT,
                "product_type_name": "TFM DevSecOps", "engagement_name": label,
                "auto_create_context": "true", "active": "true", "verified": "false",
                "minimum_severity": "Info", "close_old_findings": "false",
            })
        print(f"[import] {title}: HTTP {r.status_code}")
        if r.ok:
            imported.append({"title": title, "test": r.json().get("test"),
                             "scan_type": scan_type})
        else:
            print(r.text[:500])

    eng = dd.get_all("engagements", name=label, product__name=PRODUCT)
    eng_id = eng[0]["id"]
    findings = dd.get_all("findings", test__engagement=eng_id, related_fields="true")

    # Triaje manual: lista de reglas/ficheros considerados falsos positivos
    triage_file = Path(__file__).with_name("triage.json")
    fp_rules = json.loads(triage_file.read_text(encoding="utf-8")) if triage_file.exists() else []
    marked = []
    for fnd in findings:
        for rule in fp_rules:
            hay = " ".join(str(fnd.get(k) or "") for k in ("title", "file_path", "vuln_id_from_tool", "component_name", "description"))
            if all(tok in hay for tok in rule["match"]) and not any(tok in hay for tok in rule.get("unless", [])):
                flag = "out_of_scope" if rule.get("category") == "alcance" else "false_p"
                marked.append((fnd["id"], flag))
                break
    for fid, flag in marked:
        dd.s.patch(f"{URL}/api/v2/findings/{fid}/", json={flag: True, "active": False})
    if marked:
        findings = dd.get_all("findings", test__engagement=eng_id, related_fields="true")

    tests = {t["id"]: t["title"] for t in dd.get_all("tests", engagement=eng_id)}
    sev, by_tool, cwe, owasp = Counter(), defaultdict(Counter), Counter(), Counter()
    dup = fp = oos = 0
    for fnd in findings:
        if fnd.get("duplicate"):
            dup += 1
            continue
        if fnd.get("false_p"):
            fp += 1
            continue
        if fnd.get("out_of_scope"):
            oos += 1
            continue
        s = fnd["severity"]
        sev[s] += 1
        by_tool[tests.get(fnd["test"], str(fnd["test"]))][s] += 1
        c = fnd.get("cwe") or 0
        if c:
            cwe[c] += 1
        tool = tests.get(fnd["test"], "")
        if "Trivy" in tool:
            cat = "A06 Vulnerable and Outdated Components"
        elif "Checkov" in tool:
            cat = "A05 Security Misconfiguration"
        elif "Kyverno" in tool:
            cat = ("A08 Software and Data Integrity Failures" if c == 494
                   else "A05 Security Misconfiguration")
        elif "Gitleaks" in tool:
            cat = "A07 Identification and Authentication Failures"
        else:
            cat = CWE2OWASP.get(c, "Sin categoría (CWE no mapeado)")
        owasp[cat] += 1

    res = {
        "engagement": label, "engagement_id": eng_id, "imported": imported,
        "findings_total": len(findings), "duplicates": dup, "false_positives": fp, "out_of_scope": oos,
        "active_unique": sum(sev.values()), "by_severity": dict(sev),
        "by_tool": {k: dict(v) for k, v in by_tool.items()},
        "top_cwe": cwe.most_common(15), "owasp_top10": dict(owasp.most_common()),
        "with_cwe_pct": round(100 * sum(cwe.values()) / max(1, sum(sev.values())), 1),
    }
    (out / "dd_metrics.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: v for k, v in res.items() if k != "imported"}, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
