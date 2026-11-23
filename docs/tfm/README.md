# Laboratorio del TFM: pipeline DevSecOps para Online Boutique

Este fork de [Online Boutique](https://github.com/GoogleCloudPlatform/microservices-demo) (versión
0.10.7) es el laboratorio del Trabajo Fin de Máster *Pipeline DevSecOps con seguridad de la cadena
de suministro y control de admisión para una aplicación de microservicios en Kubernetes*
(Programa Profesional en Ciberseguridad, UNIR, 2026). El código de la aplicación es el de Google;
lo añadido para el TFM está en:

| Ruta | Contenido |
| --- | --- |
| `.github/workflows/devsecops.yml` | Pipeline: SAST (Semgrep, SonarQube), SCA (Trivy, Dependency-Check), secretos (Gitleaks), IaC (Checkov), build, análisis de imagen, SBOM, firma y procedencia, despliegue en kind con Kyverno, pruebas negativas de admisión y DAST (ZAP) |
| `.github/workflows/defectdojo.yml` | Importación de los informes de una ejecución en un DefectDojo efímero |
| `.github/workflows/deps.yml` | Flujo auxiliar para resolver dependencias de Go |
| `devsecops/` | Scripts de métricas y gates, políticas de Kyverno, triaje, riesgos aceptados y supresiones |
| `docs/tfm/` | Este documento y los scripts y datos con los que se generan las tablas de la memoria |

## Ramas y etiquetas

| Referencia | Uso |
| --- | --- |
| `baseline` (etiqueta) | Código de la aplicación sin modificar |
| `baseline-v2` | Código del estado inicial con la versión final del pipeline: mide el estado inicial |
| `main` | Estado remediado |
| `canary` | Experimento de controles positivos: `main` más cinco defectos introducidos a propósito (no se fusiona) |

## Reproducción

1. Hacer fork y habilitar GitHub Actions.
2. Crear el secreto `NVD_API_KEY` (clave gratuita de la API de la NVD). La primera ejecución
   descarga la base completa de la NVD (unas 2,5 h) y la guarda en la caché de Actions.
   No hace falta ningún otro secreto: la firma usa la identidad OIDC del workflow.
3. Estado inicial: ejecutar *DevSecOps Pipeline* sobre `baseline-v2` con `enforce_gates`
   desactivado y después activado (los gates y las políticas deben fallar).
4. Estado final: lo mismo sobre `main`. En las ejecuciones de referencia (28-10-2026), con
   `enforce_gates` se superaron todos los gates y las tres pruebas negativas de admisión fueron
   rechazadas. Como las bases de vulnerabilidades cambian, una ejecución posterior puede fallar
   por CVE publicadas después: el 23-11-2026 el mismo commit falló por CVE-2026-78661
   (golang.org/x/net) y CVE-2026-119194 (pyasn1). Se corrigieron ese mismo día (commit 5c1353b)
   y la ejecución con gates 45234109561 volvió a superarlos todos.
5. Gestión centralizada: ejecutar *DefectDojo (gestión centralizada)* con el identificador de
   cada ejecución.
6. Datos de la memoria: anotar los identificadores en `docs/tfm/resultados/runs.json` y ejecutar
   `python docs/tfm/recoger_ob.py` (requiere gh autenticado); `enriquecer_epss_kev.py` añade EPSS y KEV a las CVE.

## Ejecuciones de la memoria

Las ejecuciones de referencia son del 28-10-2026 y las repeticiones y el experimento `canary`,
del 23-11-2026. Sus identificadores están en `resultados/runs.json` y `resultados/runs_rep.json`,
y los datos agregados, en `resultados/*.json`. Los artefactos de GitHub Actions caducan a los 90
días; los datos necesarios para la memoria se conservan en este directorio.
