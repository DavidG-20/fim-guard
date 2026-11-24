"""CLI entry point for fim-guard (presentation layer using Typer + Rich)."""

from dataclasses import asdict
import json
import os
from pathlib import Path

from rich.console import Console
from rich.table import Table
import typer

from fim_guard.baseline import (
    DEFAULT_BASELINE_NAME,
    BaselineFormatError,
    BaselineTamperedError,
    check_integrity,
    create_baseline,
)
from fim_guard.models import IntegrityReport

app = typer.Typer(
    name="fim",
    help="Monitor de Integridad de Archivos (FIM) con SHA-256 y firma criptográfica HMAC-SHA256.",
    no_args_is_help=True,
)
console = Console()


def _resolve_baseline_path(target: Path, baseline: Path | None) -> Path:
    return baseline.resolve() if baseline else (target / DEFAULT_BASELINE_NAME)


def _read_secret_key(key_env: str) -> str | None:
    value = os.environ.get(key_env)
    return value.strip() if value and value.strip() else None


def _render_report(report: IntegrityReport) -> None:
    sig_labels = {
        "verified": "[green]HMAC-SHA256 verificada[/green]",
        "unsigned": "[yellow]Sin firma HMAC (define FIM_HMAC_KEY para mayor seguridad)[/yellow]",
    }
    console.print(
        f"Directorio: [bold]{report.root_dir}[/bold] | "
        f"Archivos escaneados: [bold]{report.checked_files}[/bold] | "
        f"Firma: {sig_labels.get(report.signature_status, report.signature_status)}"
    )

    if report.is_clean:
        console.print("[bold green]✔ Integridad intacta:[/bold green] no se detectaron cambios.")
        return

    table = Table(title="Alertas de integridad detectadas", show_lines=False)
    table.add_column("Severidad", style="bold")
    table.add_column("Tipo", style="cyan")
    table.add_column("Archivo", style="bold")
    table.add_column("Detalle")

    for change in report.changes:
        sev_style = "red" if change.severity == "HIGH" else "yellow"
        table.add_row(
            f"[{sev_style}]{change.severity}[/{sev_style}]",
            change.change_type,
            change.path,
            change.detail,
        )

    console.print(table)


@app.command("init")
def init_baseline(
    target: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        help="Carpeta a monitorear para generar la línea base.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Ruta donde guardar la línea base JSON (por defecto: <target>/.fim_baseline.json).",
    ),
    key_env: str = typer.Option(
        "FIM_HMAC_KEY",
        "--key-env",
        help="Nombre de la variable de entorno con la clave secreta para firmar con HMAC-SHA256.",
    ),
) -> None:
    """Escanea TARGET y genera una línea base criptográfica (SHA-256 + HMAC opcional)."""
    baseline_path = _resolve_baseline_path(target, baseline)
    secret_key = _read_secret_key(key_env)

    result = create_baseline(
        root_dir=target,
        baseline_path=baseline_path,
        secret_key=secret_key,
    )
    signed_msg = (
        "[green]firmada con HMAC-SHA256[/green]"
        if result.hmac_sha256
        else f"[yellow]sin firma HMAC[/yellow] (exporta {key_env} para firmarla)"
    )
    console.print(
        f"[green]✔ Línea base creada[/green] en [bold]{baseline_path}[/bold] "
        f"({len(result.files)} archivo(s), {signed_msg})."
    )


@app.command("check")
def check_directory(
    target: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
        help="Carpeta a verificar contra la línea base.",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Ruta del archivo de línea base JSON.",
    ),
    key_env: str = typer.Option(
        "FIM_HMAC_KEY",
        "--key-env",
        help="Variable de entorno con la clave HMAC-SHA256 para validar la firma.",
    ),
    json_out: Path | None = typer.Option(
        None,
        "--json-out",
        help="Guarda el reporte de auditoría en formato JSON en esta ruta.",
    ),
) -> None:
    """Verifica TARGET contra la línea base (exit 0=íntegro, 1=cambios, 2=manipulación/error)."""
    baseline_path = _resolve_baseline_path(target, baseline)
    secret_key = _read_secret_key(key_env)

    if not baseline_path.exists():
        console.print(
            f"[red]Error:[/red] No existe la línea base en {baseline_path}. "
            "Ejecuta primero `fim init`."
        )
        raise typer.Exit(code=2)

    try:
        report = check_integrity(
            root_dir=target,
            baseline_path=baseline_path,
            secret_key=secret_key,
            extra_excluded={json_out.resolve()} if json_out else None,
        )
    except (BaselineTamperedError, BaselineFormatError) as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(code=2) from exc

    _render_report(report)

    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(
            json.dumps(asdict(report), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[dim]Reporte JSON guardado en {json_out}[/dim]")

    if not report.is_clean:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
