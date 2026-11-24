---
name: seguridad-cripto
description: Reglas obligatorias de criptografía aplicada y lectura segura de archivos para fim-guard.
---

# Reglas de Seguridad y Criptografía (FIM)

- Calcula hashes **SHA-256** leyendo archivos en bloques (*streaming* de 64 KiB) para no agotar memoria en archivos grandes.
- Usa **HMAC-SHA256** con comparación en tiempo constante (`hmac.compare_digest`) para verificar la integridad de la línea base contra manipulación.
- **Nunca sigas enlaces simbólicos** (`is_symlink()`) para evitar bucles infinitos o escapar del directorio monitoreado.
- **Nunca modifiques ni elimines** los archivos monitoreados; `fim-guard` es estrictamente de solo lectura sobre el directorio vigilado.
- Usa códigos de salida estándar para automatización: `0` (íntegro), `1` (cambios detectados), `2` (error o línea base manipulada).
- En pruebas con `pytest`, usa siempre `tmp_path`.
