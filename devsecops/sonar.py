#!/usr/bin/env python3
"""Utilidades para el SonarQube efímero del pipeline.

  python sonar.py wait-up                    espera a que el servidor esté UP
  python sonar.py wait-ce <proyecto>...      espera a que termine el procesamiento de los análisis
  python sonar.py export <salida> <proyecto>...
      exporta los issues con impacto en seguridad y los security hotspots de los proyectos

Variables de entorno: SONAR_HOST (URL) y SONAR_TOKEN (token de usuario).
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = os.environ.get("SONAR_HOST", "http://localhost:9000").rstrip("/")


def get(path, **params):
    url = f"{HOST}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    tok = os.environ.get("SONAR_TOKEN")
    if tok:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{tok}:".encode()).decode())
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def wait_up(timeout=600):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if get("/api/system/status").get("status") == "UP":
                print("SonarQube UP")
                return
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(5)
    sys.exit("SonarQube no arrancó a tiempo")


def wait_ce(projects, timeout=900):
    end = time.time() + timeout
    for p in projects:
        while True:
            d = get("/api/ce/component", component=p)
            cur = (d.get("current") or {}).get("status")
            if not d.get("queue") and cur in ("SUCCESS", "FAILED", "CANCELED"):
                print(f"{p}: {cur}")
                if cur != "SUCCESS":
                    sys.exit(f"El análisis de {p} terminó en {cur}")
                break
            if time.time() > end:
                sys.exit(f"Tiempo agotado esperando el análisis de {p}")
            time.sleep(5)


def paged(path, key, **params):
    out, page = [], 1
    while True:
        d = get(path, p=page, ps=500, **params)
        out += d.get(key, [])
        total = d.get("paging", {}).get("total", d.get("total", 0))
        if page * 500 >= total:
            return out
        page += 1


def export(dest, projects):
    data = {"issues": [], "hotspots": []}
    for p in projects:
        data["issues"] += [dict(i, project=p) for i in
                           paged("/api/issues/search", "issues", components=p,
                                 impactSoftwareQualities="SECURITY", resolved="false")]
        data["hotspots"] += [dict(h, project=p) for h in
                             paged("/api/hotspots/search", "hotspots", project=p, status="TO_REVIEW")]
    # Estándares de cada regla (cwe:NNN, owaspTop10-2021:aN) para el mapeo en DefectDojo
    data["rules"] = {}
    for key in sorted({i["rule"] for i in data["issues"]} | {h.get("ruleKey") for h in data["hotspots"]} - {None}):
        try:
            data["rules"][key] = get("/api/rules/show", key=key).get("rule", {}).get("securityStandards", [])
        except (urllib.error.URLError, OSError, ValueError):
            data["rules"][key] = []
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    print(f"issues de seguridad: {len(data['issues'])}, hotspots: {len(data['hotspots'])}")


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "wait-up":
        wait_up()
    elif cmd == "wait-ce":
        wait_ce(args)
    elif cmd == "export":
        export(args[0], args[1:])
    else:
        sys.exit(__doc__)
