from __future__ import annotations

from datetime import datetime, timezone

import pytest

from guardian_angel import (
    ActionRequest,
    ApprovalHandler,
    ApprovalRequest,
    ApprovalRequiredError,
    ApprovalResponse,
    ApprovalStatus,
    DecisionStatus,
    GuardContext,
    GuardianAngel,
    PolicyDeniedError,
    Rule,
)
from guardian_angel.core.decision import Decision

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_approval_guard(*extra_rules):
    return GuardianAngel(
        rules=[
            Rule(
                name="approve_deploy",
                tool="deploy",
                decision=DecisionStatus.REQUIRE_APPROVAL,
            ),
            *extra_rules,
        ]
    )


class _AutoApproveHandler:
    """Always approves."""

    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.APPROVED,
            approved_by="auto",
            responded_at=datetime.now(tz=timezone.utc),
        )


class _RejectHandler:
    """Always rejects."""

    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.REJECTED,
            approved_by="auto",
            reason="rejected by policy",
            responded_at=datetime.now(tz=timezone.utc),
        )


class _ExpireHandler:
    """Always returns EXPIRED."""

    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(
            approval_id=request.approval_id,
            status=ApprovalStatus.EXPIRED,
        )


class _BrokenHandler:
    def submit(self, request: ApprovalRequest) -> ApprovalResponse:
        raise RuntimeError("approval service unavailable")


# ---------------------------------------------------------------------------
# ApprovalStatus
# ---------------------------------------------------------------------------


class TestApprovalStatus:
    def test_values(self):
        assert ApprovalStatus.APPROVED == "approved"
        assert ApprovalStatus.REJECTED == "rejected"
        assert ApprovalStatus.EXPIRED == "expired"

    def test_is_str(self):
        assert isinstance(ApprovalStatus.APPROVED, str)


# ---------------------------------------------------------------------------
# ApprovalRequest dataclass
# ---------------------------------------------------------------------------


class TestApprovalRequest:
    def _make(self, **kwargs):
        defaults = dict(
            action_request=ActionRequest(tool="deploy"),
            decision=Decision(status=DecisionStatus.REQUIRE_APPROVAL),
            requested_at=datetime.now(tz=timezone.utc),
            approval_id="approval-1",
        )
        defaults.update(kwargs)
        return ApprovalRequest(**defaults)

    def test_construction(self):
        req = self._make()
        assert req.approval_id == "approval-1"
        assert req.action_request.tool == "deploy"
        assert req.decision.status == DecisionStatus.REQUIRE_APPROVAL
        assert isinstance(req.requested_at, datetime)

    def test_approval_id_defaults_to_uuid(self):
        req = ApprovalRequest(
            action_request=ActionRequest(tool="deploy"),
            decision=Decision(status=DecisionStatus.REQUIRE_APPROVAL),
            requested_at=datetime.now(tz=timezone.utc),
        )
        assert req.approval_id

    def test_approvers_default_empty(self):
        req = self._make()
        assert req.approvers == []

    def test_approvers_custom(self):
        req = self._make(approvers=["alice", "bob"])
        assert req.approvers == ["alice", "bob"]


# ---------------------------------------------------------------------------
# ApprovalResponse dataclass
# ---------------------------------------------------------------------------


class TestApprovalResponse:
    def test_required_fields(self):
        resp = ApprovalResponse(approval_id="approval-1", status=ApprovalStatus.APPROVED)
        assert resp.approval_id == "approval-1"
        assert resp.status == ApprovalStatus.APPROVED

    def test_defaults(self):
        resp = ApprovalResponse(approval_id="approval-1", status=ApprovalStatus.APPROVED)
        assert resp.approved_by is None
        assert resp.reason is None
        assert resp.conditions == {}
        assert resp.responded_at is None

    def test_all_fields(self):
        now = datetime.now(tz=timezone.utc)
        resp = ApprovalResponse(
            approval_id="approval-2",
            status=ApprovalStatus.REJECTED,
            approved_by="alice",
            reason="too risky",
            conditions={"require_review": True},
            responded_at=now,
        )
        assert resp.approved_by == "alice"
        assert resp.reason == "too risky"
        assert resp.conditions == {"require_review": True}
        assert resp.responded_at == now


# ---------------------------------------------------------------------------
# ApprovalHandler protocol
# ---------------------------------------------------------------------------


class TestApprovalHandlerProtocol:
    def test_class_with_submit_satisfies_protocol(self):
        class MyHandler:
            def submit(self, request: ApprovalRequest) -> ApprovalResponse:
                return ApprovalResponse(
                    approval_id=request.approval_id,
                    status=ApprovalStatus.APPROVED,
                )

        assert isinstance(MyHandler(), ApprovalHandler)

    def test_class_without_submit_does_not_satisfy_protocol(self):
        class NotAHandler:
            pass

        assert not isinstance(NotAHandler(), ApprovalHandler)

    def test_auto_approve_handler_satisfies_protocol(self):
        assert isinstance(_AutoApproveHandler(), ApprovalHandler)

    def test_reject_handler_satisfies_protocol(self):
        assert isinstance(_RejectHandler(), ApprovalHandler)


# ---------------------------------------------------------------------------
# GuardianAngel.request_approval()
# ---------------------------------------------------------------------------


class TestRequestApproval:
    def test_approved_returns_response(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=_AutoApproveHandler(),
        )
        request = ActionRequest(tool="deploy", request_id="req-42")
        response = guard.request_approval(request)
        assert response.status == ApprovalStatus.APPROVED
        assert response.approval_id
        assert response.approval_id != "req-42"

    def test_rejected_returns_response(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=_RejectHandler(),
        )
        response = guard.request_approval(ActionRequest(tool="deploy"))
        assert response.status == ApprovalStatus.REJECTED

    def test_no_handler_raises_approval_required_error(self):
        guard = _require_approval_guard()
        with pytest.raises(ApprovalRequiredError) as exc_info:
            guard.request_approval(ActionRequest(tool="deploy"))
        assert exc_info.value.decision.status == DecisionStatus.REQUIRE_APPROVAL

    def test_allow_decision_raises_value_error(self):
        guard = GuardianAngel(rules=[])  # no rules → ALLOW
        with pytest.raises(ValueError, match="already allowed"):
            guard.request_approval(ActionRequest(tool="anything"))

    def test_deny_decision_raises_policy_denied_error(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="nuke", decision=DecisionStatus.DENY)]
        )
        with pytest.raises(PolicyDeniedError) as exc_info:
            guard.request_approval(ActionRequest(tool="nuke"))
        assert exc_info.value.decision.status == DecisionStatus.DENY

    def test_action_request_id_preserved_and_approval_id_is_distinct(self):
        submitted = []

        class CapturingHandler:
            def submit(self, request: ApprovalRequest) -> ApprovalResponse:
                submitted.append(request)
                return ApprovalResponse(
                    approval_id=request.approval_id,
                    status=ApprovalStatus.APPROVED,
                )

        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=CapturingHandler(),
        )
        guard.request_approval(ActionRequest(tool="deploy", request_id="my-id"))
        assert submitted[0].action_request.request_id == "my-id"
        assert submitted[0].approval_id != "my-id"

    def test_approval_id_generated_when_not_provided(self):
        submitted = []

        class CapturingHandler:
            def submit(self, request: ApprovalRequest) -> ApprovalResponse:
                submitted.append(request)
                return ApprovalResponse(
                    approval_id=request.approval_id,
                    status=ApprovalStatus.APPROVED,
                )

        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=CapturingHandler(),
        )
        guard.request_approval(ActionRequest(tool="deploy"))
        assert submitted[0].approval_id

    def test_explicit_approval_id_is_supported(self):
        req = ApprovalRequest(
            action_request=ActionRequest(tool="deploy"),
            decision=Decision(status=DecisionStatus.REQUIRE_APPROVAL),
            requested_at=datetime.now(tz=timezone.utc),
            approval_id="approval-123",
        )
        assert req.approval_id == "approval-123"

    def test_approval_backend_failure_defaults_to_deny(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=_BrokenHandler(),
        )
        with pytest.raises(PolicyDeniedError) as exc_info:
            guard.request_approval(ActionRequest(tool="deploy"))
        assert exc_info.value.decision.source == "approval_error"

    def test_approval_backend_failure_can_fallback_to_allow(self):
        from guardian_angel import GuardConfig

        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=_BrokenHandler(),
            config=GuardConfig(on_approval_error=DecisionStatus.ALLOW),
        )
        response = guard.request_approval(ActionRequest(tool="deploy"))
        assert response.status == ApprovalStatus.APPROVED
        assert response.approved_by == "guardian_angel_fallback"

    def test_approval_backend_failure_can_require_approval(self):
        from guardian_angel import GuardConfig

        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=_BrokenHandler(),
            config=GuardConfig(on_approval_error=DecisionStatus.REQUIRE_APPROVAL),
        )
        with pytest.raises(ApprovalRequiredError) as exc_info:
            guard.request_approval(ActionRequest(tool="deploy"))
        assert exc_info.value.decision.source == "approval_error"


# ---------------------------------------------------------------------------
# from_yaml classmethod
# ---------------------------------------------------------------------------


class TestFromYaml:
    def test_from_yaml_accepts_approval_handler(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            "rules:\n"
            "  - name: approve_deploy\n"
            "    tool: deploy\n"
            "    decision: require_approval\n"
        )
        guard = GuardianAngel.from_yaml(
            str(policy), approval_handler=_AutoApproveHandler()
        )
        assert guard.approval_handler is not None
        response = guard.request_approval(ActionRequest(tool="deploy"))
        assert response.status == ApprovalStatus.APPROVED

    def test_from_yaml_default_no_handler(self, tmp_path):
        policy = tmp_path / "policy.yaml"
        policy.write_text("rules: []\n")
        guard = GuardianAngel.from_yaml(str(policy))
        assert guard.approval_handler is None


# ---------------------------------------------------------------------------
# guard.invoke() integration
# ---------------------------------------------------------------------------


class TestInvokeWithApproval:
    def test_auto_approve_executes_function(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=_AutoApproveHandler(),
        )

        def deploy(target):
            assert target == "prod"
            return f"deployed {target}"

        result = guard.invoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))
        assert result == "deployed prod"

    def test_reject_raises_policy_denied_error(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=_RejectHandler(),
        )

        def deploy(target):
            assert target == "prod"
            return "deployed"

        with pytest.raises(PolicyDeniedError):
            guard.invoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))

    def test_expired_raises_policy_denied_error(self):
        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=_ExpireHandler(),
        )

        def deploy(target):
            assert target == "prod"
            return "deployed"

        with pytest.raises(PolicyDeniedError):
            guard.invoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))

    def test_no_handler_raises_approval_required_error(self):
        guard = _require_approval_guard()

        def deploy(target):
            return f"deployed {target}"

        with pytest.raises(ApprovalRequiredError):
            guard.invoke(deploy, "prod", guard_ctx=GuardContext(tool="deploy"))

    def test_handler_receives_correct_request_id(self):
        captured = []

        class CapturingHandler:
            def submit(self, request: ApprovalRequest) -> ApprovalResponse:
                captured.append(request)
                return ApprovalResponse(
                    approval_id=request.approval_id,
                    status=ApprovalStatus.APPROVED,
                )

        guard = GuardianAngel(
            rules=[Rule(name="r", tool="deploy", decision=DecisionStatus.REQUIRE_APPROVAL)],
            approval_handler=CapturingHandler(),
        )

        def deploy(target):
            assert target == "prod"
            return "deployed"

        guard.invoke(
            deploy, "prod",
            guard_ctx=GuardContext(tool="deploy", request_id="tool-req-1"),
        )
        assert captured[0].approval_id
        assert captured[0].action_request.request_id == "tool-req-1"
        assert captured[0].action_request.tool == "deploy"
