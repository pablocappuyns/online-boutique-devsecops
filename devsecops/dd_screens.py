#!/usr/bin/env python3
"""Capturas de DefectDojo para la memoria (figuras del cap. 5.5 / 6).

Uso: python dd_screens.py <engagement_id> <dir_salida>
Variables de entorno: DD_URL, DD_USER, DD_PASS.
"""
import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

URL = os.environ.get("DD_URL", "http://localhost:8080").rstrip("/")


def main():
    eng, out = sys.argv[1], Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1600, "height": 1000})
        pg.goto(f"{URL}/login")
        pg.fill("#id_username", os.environ["DD_USER"])
        pg.fill("#id_password", os.environ["DD_PASS"])
        pg.click("button[type=submit], input[type=submit]")
        pg.wait_for_load_state("networkidle")
        shots = {
            "dd_dashboard.png": f"{URL}/dashboard",
            "dd_engagement.png": f"{URL}/engagement/{eng}",
            "dd_findings.png": f"{URL}/finding/open?test__engagement={eng}&o=numerical_severity",
            "dd_metrics.png": f"{URL}/metrics/all",
        }
        for name, url in shots.items():
            try:
                pg.goto(url, timeout=60000)
                pg.wait_for_load_state("networkidle", timeout=60000)
                pg.screenshot(path=str(out / name), full_page=False)
                print("captura", name)
            except Exception as e:  # una captura fallida no invalida el resto
                print("fallo", name, e)
        b.close()


if __name__ == "__main__":
    main()
