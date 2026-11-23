#!/usr/bin/env python3
"""Gate de SonarQube y Dependency-Check con la misma normalización que metrics.py.

Uso: python gate.py <sonar|depcheck> <dir_artefactos>
Falla (código 1) si hay hallazgos Critical o High que no estén suprimidos como falsos positivos
(devsecops/dc-suppressions.xml) ni aceptados en devsecops/accepted.json
(lista de {"control", "match": [fragmentos], "reason", "compensating_control", "expires"};
un hallazgo se acepta si todos los fragmentos aparecen en su descripción y la aceptación no ha
caducado: a partir de la fecha "expires" (AAAA-MM-DD) el hallazgo vuelve a bloquear).
"""
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import metrics  # noqa: E402

ctrl, art = sys.argv[1], Path(sys.argv[2])
_, items = {"sonar": metrics.sonar, "depcheck": metrics.depcheck}[ctrl](art)
acc_path = Path(__file__).parent / "accepted.json"
today = datetime.date.today().isoformat()
accepted = []
for a in (json.loads(acc_path.read_text(encoding="utf-8")) if acc_path.exists() else []):
    if a["control"] != ctrl:
        continue
    if a.get("expires") and a["expires"] < today:
        print(f"Aceptación caducada el {a['expires']}: {' + '.join(a['match'])}")
        continue
    accepted.append(a)
blocking = []
for it in items:
    # Los falsos positivos suprimidos en dc-suppressions.xml no bloquean
    if it["sev"] not in ("Critical", "High") or it.get("suppressed"):
        continue
    hay = " ".join(str(v) for v in it.values() if v)
    if any(all(t in hay for t in a["match"]) for a in accepted):
        continue
    blocking.append(it)
for it in blocking:
    print(f"{it['sev']}: {it.get('rule') or it.get('id')} {it.get('file') or it.get('pkg')}"
          f"{':' + str(it['line']) if it.get('line') else ''}")
print(f"{ctrl}: {len(blocking)} hallazgos Critical/High no aceptados")
sys.exit(1 if blocking else 0)
