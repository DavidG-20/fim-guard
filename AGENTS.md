# Reglas del proyecto `fim-guard`

- Stack: **Python 3.12+**, **`uv`**, **Typer**, **Rich** y biblioteca estándar (`hashlib`, `hmac`, `pathlib`).
- Código interno en **inglés técnico**; documentación (`README.md`) y mensajes de consola en **español**.
- Nunca guardes claves HMAC en el repositorio ni las recibas por argumentos de línea de comandos; usa variables de entorno (`FIM_HMAC_KEY`) o archivos protegidos.
- Consulta `.agents/skills/seguridad-cripto/SKILL.md` para reglas de criptografía y lectura segura de archivos.
