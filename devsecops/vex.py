#!/usr/bin/env python3
"""Genera el documento VEX (OpenVEX 0.2.0) de una imagen a partir de devsecops/accepted.json.

Un VEX (Vulnerability Exploitability eXchange) declara, de forma legible por máquina, por qué una
vulnerabilidad presente en un artefacto no es explotable en él o qué se hace al respecto
(CISA, 2023; OpenVEX, 2024). Aquí convierte las excepciones del gate —hasta ahora propias del
proyecto (accepted.json, .trivyignore)— en un formato interoperable que consume Trivy (--vex),
se atesta con cosign junto al SBOM y verifica Kyverno en la admisión.

Solo se emiten las aceptaciones con identificador de vulnerabilidad (campo "vex") y no caducadas:
al caducar desaparecen del VEX y el hallazgo vuelve a bloquear el gate.

Uso: python3 devsecops/vex.py <imagen@sha256:...> <salida.json> [<servicio>]
"""
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
# El autor del documento es el repositorio: la política de admisión lo compara con __REPO_URL__
AUTHOR = (os.environ.get("GITHUB_SERVER_URL", "https://github.com") + "/"
          + os.environ.get("GITHUB_REPOSITORY", "pablocappuyns/online-boutique-devsecops"))
CONTEXT = "https://openvex.dev/ns/v0.2.0"
# Justificaciones admitidas por OpenVEX para el estado not_affected
JUSTIFICATIONS = {
    "component_not_present", "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


def purl_oci(ref):
    """pkg:oci/<nombre>@<digest>?repository_url=<registro>/<nombre> a partir de imagen@digest."""
    name_part, digest = ref.split("@", 1)
    name = name_part.rsplit("/", 1)[-1].split(":", 1)[0]
    return f"pkg:oci/{name}@{digest}?repository_url={name_part}"


def statements(ref, today):
    accepted = json.loads((BASE / "accepted.json").read_text(encoding="utf-8"))
    img = purl_oci(ref)
    out = []
    for a in accepted:
        vex = a.get("vex")
        if not vex:
            continue
        if a.get("expires") and a["expires"] < today:
            continue
        just = vex.get("justification", "vulnerable_code_not_in_execute_path")
        if just not in JUSTIFICATIONS:
            raise SystemExit(f"Justificación OpenVEX no válida: {just}")
        subs = [{"@id": s} for s in vex.get("subcomponents", [])]
        base = {
            "vulnerability": {"name": vex["vulnerability"]},
            "status": "not_affected",
            "justification": just,
            "impact_statement": a.get("compensating_control", a.get("reason", "")),
            "timestamp": a.get("reviewed", today) + "T00:00:00Z",
        }
        if "aliases" in vex:
            base["vulnerability"]["aliases"] = vex["aliases"]
        # Dos sentencias por aceptación: sobre la imagen (con el paquete como subcomponente) y
        # sobre el propio paquete, para que el emparejamiento no dependa de cómo el consumidor
        # construya el purl de la imagen.
        st = dict(base, products=[dict({"@id": img}, **({"subcomponents": subs} if subs else {}))])
        out.append(st)
        for s in vex.get("subcomponents", []):
            out.append(dict(base, products=[{"@id": s}]))
    return out


def main():
    ref, dst = sys.argv[1], Path(sys.argv[2])
    today = datetime.date.today().isoformat()
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    sts = statements(ref, today)
    doc = {
        "@context": CONTEXT,
        "@id": "",
        "author": AUTHOR,
        "role": "Equipo DevSecOps del proyecto",
        "timestamp": now,
        "version": 1,
        "tooling": "devsecops/vex.py",
        "statements": sts,
    }
    # El identificador recomendado por OpenVEX es un hash del contenido canónico
    doc["@id"] = "https://openvex.dev/docs/public/vex-" + hashlib.sha256(
        json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"VEX: {len(sts)} sentencias para {ref} -> {dst}")


if __name__ == "__main__":
    main()
