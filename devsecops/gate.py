#!/usr/bin/env python3
"""Gate de SonarQube y Dependency-Check con la misma normalización que metrics.py.

Uso: python gate.py <sonar|depcheck> <dir_artefactos>
Falla (código 1) si hay hallazgos Critical o High que no estén aceptados en devsecops/accepted.json
(lista de {"control", "match": [fragmentos], "reason"}; un hallazgo se acepta si todos los
fragmentos aparecen en su descripción).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import metrics  # noqa: E402

ctrl, art = sys.argv[1], Path(sys.argv[2])
_, items = {"sonar": metrics.sonar, "depcheck": metrics.depcheck}[ctrl](art)
acc_path = Path(__file__).parent / "accepted.json"
accepted = [a for a in (json.loads(acc_path.read_text(encoding="utf-8")) if acc_path.exists() else [])
            if a["control"] == ctrl]
blocking = []
for it in items:
    if it["sev"] not in ("Critical", "High"):
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
