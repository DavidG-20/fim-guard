# fim-guard — Monitor de Integridad de Archivos (FIM)

Herramienta defensiva de **Ciberseguridad (Blue Team / Linux)** escrita en Python que calcula huellas criptográficas **SHA-256** de tus archivos críticos, firma la línea base con **HMAC-SHA256** y detecta manipulaciones no autorizadas (archivos modificados, eliminados, inyectados o con permisos alterados).

## ¿Por qué existe un FIM?

En seguridad defensiva (*Wazuh*, *AIDE*, *Tripwire*), un **File Integrity Monitor (FIM)** permite responder rápidamente a la pregunta: *"¿Alguien alteró archivos de configuración, binarios o código fuente sin permiso?"*.  
Al firmar la línea base con **HMAC-SHA256**, incluso si un atacante intenta modificar un archivo **y** reescribir su hash en `.fim_baseline.json`, la verificación criptográfica detecta la manipulación al instante.

## Características principales

- **Hashing SHA-256 en streaming (64 KiB)**: procesa archivos grandes sin consumir memoria innecesaria.
- **Firma criptográfica HMAC-SHA256**: verifica la autenticidad de la línea base usando comparación en tiempo constante (`hmac.compare_digest`) y lectura segura desde variable de entorno (`FIM_HMAC_KEY`, nunca expuesta en argumentos CLI).
- **Detección en 4 categorías**:
  - `modified` (`HIGH`): cambio en el contenido (hash SHA-256 distinto).
  - `deleted` (`HIGH`): archivo eliminado del directorio vigilado.
  - `added` (`MEDIUM`): archivo nuevo no registrado en la línea base.
  - `permissions_changed` (`MEDIUM`): permisos POSIX alterados (`chmod`) sin cambiar el contenido.
- **Seguro por diseño**: solo lectura sobre el directorio vigilado e ignora enlaces simbólicos (`symlink`) para evitar bucles o escapes de ruta.
- **Códigos de salida para automatización / cron / CI**:
  - `0`: integridad intacta.
  - `1`: se detectaron cambios en archivos.
  - `2`: error o **línea base manipulada** (fallo de firma HMAC).
- **Exportación JSON (`--json-out`)**: genera reportes estructurados para integrar con otros sistemas o SIEMs.

## Arquitectura

```text
fim-guard/
├── .agents/skills/seguridad-cripto/   # Reglas de criptografía y lectura segura
├── AGENTS.md                          # Reglas generales del proyecto
├── src/fim_guard/
│   ├── main.py                        # Interfaz CLI (Typer + Rich)
│   ├── models.py                      # Dataclasses tipados (FileRecord, Baseline, IntegrityReport)
│   ├── crypto.py                      # SHA-256 en streaming y HMAC-SHA256 en tiempo constante
│   ├── scanner.py                     # Escáner recursivo seguro (sin seguir symlinks)
│   └── baseline.py                    # Generación, verificación HMAC y motor de diferencias
└── tests/
    └── test_fim.py                    # Pruebas de integridad, manipulación HMAC y symlinks
```

## Instalación

Asegúrate de tener [`uv`](https://docs.astral.sh/uv/) instalado:

```bash
git clone https://github.com/DavidG-20/fim-guard.git
cd fim-guard
uv sync
```

## Uso rápido

1. **Define una clave secreta HMAC en tu sesión (recomendado):**
   ```bash
   export FIM_HMAC_KEY="mi-clave-secreta-larga-y-aleatoria"
   ```

2. **Crea la línea base de una carpeta:**
   ```bash
   uv run fim init /ruta/a/carpeta
   ```

3. **Verifica la integridad más tarde (con reporte JSON opcional):**
   ```bash
   uv run fim check /ruta/a/carpeta --json-out reporte_fim.json
   ```

## Ejecutar pruebas automatizadas

```bash
uv run pytest -v
```

## Licencia

MIT
