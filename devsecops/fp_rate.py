#!/usr/bin/env python3
"""Tasa de falsos positivos (OE4) aplicando el triaje de triage.json a metrics.json.

Uso: python fp_rate.py <metrics.json> [<salida.json>]
Un hallazgo coincide con una regla si TODOS sus fragmentos aparecen en su descripción
(herramienta + regla + fichero + nombre). Las reglas de categoría "fp" marcan falsos
positivos; las de categoría "alcance", verdaderos positivos excluidos por alcance. Los hallazgos de severidad
Info se excluyen del cálculo por no constituir vulnerabilidades.
"""
import json
import sys
from collections import Counter
from pathlib import Path

rules = json.loads(Path(__file__).with_name("triage.json").read_text(encoding="utf-8"))
m = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

total, fp, oos, reasons = Counter(), Counter(), Counter(), Counter()
for ctl in m["controls"]:
    if not ctl.get("available") or not ctl.get("in_total"):
        continue
    for it in ctl["items"]:
        if it.get("sev") == "Info":
            continue
        hay = " ".join(str(v) for v in [ctl["tool"], *it.values()] if v)
        total[ctl["tool"]] += 1
        for r in rules:
            if all(tok in hay for tok in r["match"]) and not any(tok in hay for tok in r.get("unless", [])):
                # "fp" = falso positivo; "alcance" = verdadero positivo excluido por alcance
                (oos if r.get("category") == "alcance" else fp)[ctl["tool"]] += 1
                reasons[r["reason"]] += 1
                break

out = {"by_tool": {t: {"total": total[t], "fp": fp[t], "out_of_scope": oos[t],
                       "fp_pct": round(100 * fp[t] / total[t], 1) if total[t] else 0.0}
                   for t in total},
       "total": sum(total.values()), "fp": sum(fp.values()), "out_of_scope": sum(oos.values()),
       "fp_pct": round(100 * sum(fp.values()) / max(1, sum(total.values())), 1),
       "reasons": dict(reasons.most_common())}
print(json.dumps(out, indent=1, ensure_ascii=False))
if len(sys.argv) > 2:
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
