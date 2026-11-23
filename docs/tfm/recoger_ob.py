# -*- coding: utf-8 -*-
"""Recoge los resultados de las ejecuciones de referencia del pipeline (caso Online Boutique).

Lee resultados/runs.json ({"clave": id_run, ...}), descarga con gh los artefactos
'metrics' y 'admission-kyverno' de cada ejecución y, mediante la API, la duración de cada
trabajo. Escribe resultados/resultados.json, del que salen las tablas y figuras de la memoria.
Uso: python recoger_ob.py [runs.json] [salida.json]
  (por defecto resultados/runs.json y resultados/resultados.json; las repeticiones del
  23-11-2026 y el experimento canary usan runs_rep.json y resultados_rep.json)
"""
import sys
import json
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

REPO = "pablocappuyns/online-boutique-devsecops"
BASE = Path(__file__).resolve().parent
OUT = BASE / "resultados"


def gh(*args):
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True,
                          encoding="utf-8").stdout


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def durations(run_id):
    run = json.loads(gh("api", f"repos/{REPO}/actions/runs/{run_id}"))
    jobs = json.loads(gh("api", f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100"))["jobs"]
    out = {"head_sha": run["head_sha"][:7], "event": run["event"], "conclusion": run["conclusion"],
           "created_at": run["created_at"], "jobs": {}}
    starts, ends = [], []
    for j in jobs:
        a, b = ts(j.get("started_at")), ts(j.get("completed_at"))
        if a and b:
            out["jobs"][j["name"]] = {"s": int((b - a).total_seconds()), "conclusion": j["conclusion"]}
            starts.append(a); ends.append(b)
    out["wall_s"] = int((max(ends) - min(starts)).total_seconds()) if starts else None
    # Minutos facturables equivalentes (cada trabajo se redondea al minuto superior)
    out["billable_min"] = sum(-(-v["s"] // 60) for v in out["jobs"].values())
    return out


def artifact(run_id, name, files):
    with tempfile.TemporaryDirectory() as d:
        try:
            gh("run", "download", str(run_id), "-R", REPO, "-n", name, "-D", d)
        except subprocess.CalledProcessError:
            return {}
        res = {}
        for f in files:
            p = Path(d) / f
            if p.exists():
                txt = p.read_text(encoding="utf-8")
                res[f] = json.loads(txt) if f.endswith(".json") else txt
        return res


def main():
    src = OUT / (sys.argv[1] if len(sys.argv) > 1 else "runs.json")
    dst = OUT / (sys.argv[2] if len(sys.argv) > 2 else "resultados.json")
    runs = json.loads(src.read_text(encoding="utf-8"))
    res = {"repo": REPO, "runs": {}}
    for key, rid in runs.items():
        print("run", key, rid)
        r = {"id": rid, "durations": durations(rid)}
        if key.startswith("dd_"):
            dd = artifact(rid, f"defectdojo-{rid}", ["dd_metrics.json"])
            r["dd"] = dd.get("dd_metrics.json")
            res["runs"][key] = r
            continue
        m = artifact(rid, "metrics", ["metrics.json"])
        if m:
            r["metrics"] = m["metrics.json"]
        r["admission"] = artifact(rid, "admission-kyverno",
                                  ["supply-chain.txt", "negative-tests.json", "apply.txt", "deployments.txt"])
        res["runs"][key] = r
    dst.write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    print("ok", dst)


if __name__ == "__main__":
    main()
