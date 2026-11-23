# -*- coding: utf-8 -*-
"""Enriquece con EPSS (FIRST) y KEV (CISA) las CVE de las ejecuciones de referencia.

EPSS se consulta en la fecha de las ejecuciones (28-10-2026) para que el resultado sea
reproducible; KEV se descarga en su versión actual y se registra la fecha del catálogo.
Salida: resultados/epss_kev.json
"""
import json
import os
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(BASE, "resultados")
FECHA = "2026-10-28"


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "tfm-unir"}), timeout=60) as r:
        return json.load(r)


cves = sorted(set(json.load(open(os.path.join(RES, "cves_baseline.json")))) |
              set(json.load(open(os.path.join(RES, "cves_remediado.json")))))
epss = {}
for i in range(0, len(cves), 80):
    d = get("https://api.first.org/data/v1/epss?date=%s&cve=%s" % (FECHA, ",".join(cves[i:i + 80])))
    for x in d["data"]:
        epss[x["cve"]] = {"epss": float(x["epss"]), "percentile": float(x["percentile"])}
kev = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
kev_ids = {v["cveID"]: v["dateAdded"] for v in kev["vulnerabilities"]}
out = {"epss_date": FECHA, "kev_catalog_version": kev.get("catalogVersion"),
       "kev_date_released": kev.get("dateReleased"),
       "cves": {c: {**epss.get(c, {}), "kev": c in kev_ids, "kev_added": kev_ids.get(c)} for c in cves}}
json.dump(out, open(os.path.join(RES, "epss_kev.json"), "w"), indent=1)
print(len(cves), "CVE;", len(epss), "con EPSS;", sum(1 for c in cves if c in kev_ids), "en KEV;",
      "catálogo", out["kev_catalog_version"])
