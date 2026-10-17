"""Small, explainable checks for common IAM policy misconfigurations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    statement: int
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PRIVILEGE_MANAGEMENT_ACTIONS = {
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:createaccesskey",
    "iam:createpolicyversion",
    "iam:passrole",
    "iam:putgrouppolicy",
    "iam:putrolepolicy",
    "iam:putuserpolicy",
    "iam:setdefaultpolicyversion",
}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _has_wildcard(value: Any) -> bool:
    return any(isinstance(item, str) and item.strip() == "*" for item in _as_list(value))


def _has_action_prefix_wildcard(value: Any) -> bool:
    return any(
        isinstance(item, str) and item.strip().endswith(":*")
        for item in _as_list(value)
    )


def _contains_wildcard_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(_has_wildcard(value) for value in principal.values())
    return False


def _actions(value: Any) -> set[str]:
    return {
        item.strip().lower()
        for item in _as_list(value)
        if isinstance(item, str)
    }


def analyze_policy(document: Any) -> list[Finding]:
    """Return findings for selected risky patterns in an IAM policy document.

    This intentionally does not attempt to reproduce AWS policy evaluation.
    It checks a small set of high-signal patterns and leaves context-dependent
    decisions to a reviewer.
    """
    if not isinstance(document, dict):
        raise ValueError("A política precisa ser um objeto JSON.")

    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise ValueError("A política precisa conter Statement como objeto ou lista.")

    findings: list[Finding] = []
    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            raise ValueError(f"Statement {index} precisa ser um objeto JSON.")
        if str(statement.get("Effect", "")).lower() != "allow":
            continue

        actions = statement.get("Action")
        resources = statement.get("Resource")
        principal = statement.get("Principal")
        has_wildcard_action = _has_wildcard(actions)
        has_action_prefix_wildcard = _has_action_prefix_wildcard(actions)
        has_wildcard_resource = _has_wildcard(resources)

        if has_wildcard_action and has_wildcard_resource:
            findings.append(
                Finding(
                    rule_id="IAM001",
                    severity="CRITICAL",
                    title="Permissão ampla para qualquer ação e recurso",
                    detail="A declaração Allow combina Action '*' com Resource '*'.",
                    statement=index,
                    recommendation=(
                        "Substitua os curingas pelas ações e recursos estritamente necessários."
                    ),
                )
            )
        else:
            if has_wildcard_action:
                findings.append(
                    Finding(
                        rule_id="IAM002",
                        severity="HIGH",
                        title="Todas as ações estão permitidas",
                        detail="A declaração Allow contém Action '*'.",
                        statement=index,
                        recommendation=(
                            "Defina uma lista explícita de ações necessárias à tarefa."
                        ),
                    )
                )
            elif has_action_prefix_wildcard:
                findings.append(
                    Finding(
                        rule_id="IAM003",
                        severity="MEDIUM",
                        title="Todas as ações de um serviço estão permitidas",
                        detail="A declaração Allow contém uma ação com sufixo ':*'.",
                        statement=index,
                        recommendation=(
                            "Troque o curinga do serviço pelas ações específicas necessárias."
                        ),
                    )
                )

            if has_wildcard_resource:
                findings.append(
                    Finding(
                        rule_id="IAM004",
                        severity="HIGH",
                        title="A permissão se aplica a qualquer recurso",
                        detail="A declaração Allow contém Resource '*'.",
                        statement=index,
                        recommendation=(
                            "Restrinja Resource aos ARNs necessários sempre que o serviço permitir."
                        ),
                    )
                )

        if _contains_wildcard_principal(principal):
            condition = statement.get("Condition")
            has_condition = isinstance(condition, dict) and bool(condition)
            findings.append(
                Finding(
                    rule_id="IAM005",
                    severity="HIGH" if has_condition else "CRITICAL",
                    title="Acesso concedido a qualquer principal",
                    detail=(
                        "A declaração Allow usa Principal '*'. "
                        + (
                            "Existe uma Condition; ainda assim, revise se ela limita o acesso."
                            if has_condition
                            else "Nenhuma Condition limita explicitamente essa declaração."
                        )
                    ),
                    statement=index,
                    recommendation=(
                        "Restrinja Principal a contas, funções ou serviços conhecidos e "
                        "mantenha condições necessárias, como origem ou organização."
                    ),
                )
            )

        risky_actions = sorted(_actions(actions) & PRIVILEGE_MANAGEMENT_ACTIONS)
        if risky_actions:
            findings.append(
                Finding(
                    rule_id="IAM006",
                    severity="HIGH",
                    title="Ações de gerenciamento de permissões detectadas",
                    detail="A declaração permite: " + ", ".join(risky_actions) + ".",
                    statement=index,
                    recommendation=(
                        "Confirme que essas ações são indispensáveis e limite quem pode usá-las."
                    ),
                )
            )

    return findings
