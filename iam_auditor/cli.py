"""Command-line interface for the IAM policy auditor."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .audit import Finding, analyze_policy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-audit",
        description="Analisa localmente políticas AWS IAM em JSON.",
        epilog="A ferramenta é educativa: não substitui IAM Access Analyzer ou revisão especializada.",
    )
    parser.add_argument("policy", type=Path, help="Arquivo JSON da política IAM")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Formato da saída (padrão: text)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Retorna código 1 se forem encontrados riscos.",
    )
    parser.add_argument(
        "--version", action="version", version=f"iam-audit {__version__}"
    )
    return parser


def _render_text(path: Path, findings: list[Finding]) -> str:
    if not findings:
        return f"✓ Nenhum padrão de risco identificado em {path}."

    lines = [f"Análise de {path}: {len(findings)} achado(s)", ""]
    for finding in findings:
        lines.extend(
            [
                f"[{finding.severity}] {finding.rule_id} — {finding.title}",
                f"  Declaração: {finding.statement}",
                f"  Detalhe: {finding.detail}",
                f"  Recomendação: {finding.recommendation}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = json.loads(args.policy.read_text(encoding="utf-8"))
        findings = analyze_policy(document)
    except FileNotFoundError:
        print(f"Erro: arquivo não encontrado: {args.policy}", file=sys.stderr)
        return 2
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Erro ao analisar a política: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        result = {
            "file": str(args.policy),
            "findings_count": len(findings),
            "findings": [finding.to_dict() for finding in findings],
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(_render_text(args.policy, findings))

    return 1 if args.strict and findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
