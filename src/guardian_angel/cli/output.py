from __future__ import annotations

from guardian_angel.core.decision import Decision, DecisionStatus
from guardian_angel.core.request import ActionRequest


def _status_style(status: DecisionStatus) -> str:
    if status == DecisionStatus.ALLOW:
        return "green"
    if status == DecisionStatus.DENY:
        return "red"
    return "yellow"


def render_decision(decision: Decision, *, explain: bool) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    style = _status_style(decision.status)

    if not explain:
        console.print(f"[{style} bold]{decision.status.value}[/{style} bold]")
        return

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="dim")
    table.add_column()
    table.add_row("status", f"[{style} bold]{decision.status.value}[/{style} bold]")
    table.add_row("rule", decision.rule_name or "<none>")
    table.add_row("reason", decision.reason or "<none>")

    console.print(table)


def render_verbose_context(
    *,
    policy_path: str,
    request_path: str,
    request: ActionRequest,
) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="dim")
    table.add_column()
    table.add_row("policy", policy_path)
    table.add_row("request", request_path)
    table.add_row("tool", request.tool)
    table.add_row("request_id", request.request_id or "<none>")
    table.add_row("attributes", str(len(request.attributes)))
    console.print(table)