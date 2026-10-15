"""jarvis/policy/engine.py — Default-Deny Policy & Standing Mandates Engine."""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional
from jarvis.contracts import (
    AutonomyLevel,
    AuthorizationDecision,
    DataClass,
    PolicyEngineProtocol,
    PolicyRequest,
    RiskTier,
    SafetyKernelProtocol,
    StoreProtocol,
    canonical_hash,
    redact_secrets,
    utc_now,
)

DEFAULT_ACTION_CATALOG: Dict[str, RiskTier] = {
    # R0 Read-Only
    "fs.read": RiskTier.R0_READ_ONLY,
    "fs.list": RiskTier.R0_READ_ONLY,
    "code.search": RiskTier.R0_READ_ONLY,
    "code.repo_map": RiskTier.R0_READ_ONLY,
    "pc.list_apps": RiskTier.R0_READ_ONLY,
    "pc.dump_tree": RiskTier.R0_READ_ONLY,
    "pc.screenshot": RiskTier.R0_READ_ONLY,
    "web.navigate": RiskTier.R0_READ_ONLY,
    "web.extract": RiskTier.R0_READ_ONLY,
    "inbox.read": RiskTier.R0_READ_ONLY,
    "calendar.read": RiskTier.R0_READ_ONLY,
    "finance.analyze": RiskTier.R0_READ_ONLY,
    "device.read": RiskTier.R0_READ_ONLY,
    "model.generate": RiskTier.R0_READ_ONLY,
    # R1 Local Reversible
    "fs.write": RiskTier.R1_LOCAL_REVERSIBLE,
    "fs.trash": RiskTier.R1_LOCAL_REVERSIBLE,
    "code.patch": RiskTier.R1_LOCAL_REVERSIBLE,
    "code.test": RiskTier.R1_LOCAL_REVERSIBLE,
    "pc.focus": RiskTier.R1_LOCAL_REVERSIBLE,
    "pc.click": RiskTier.R1_LOCAL_REVERSIBLE,
    "pc.type": RiskTier.R1_LOCAL_REVERSIBLE,
    "web.fill": RiskTier.R1_LOCAL_REVERSIBLE,
    "inbox.draft": RiskTier.R1_LOCAL_REVERSIBLE,
    "calendar.create_local": RiskTier.R1_LOCAL_REVERSIBLE,
    "device.light": RiskTier.R1_LOCAL_REVERSIBLE,
    "device.thermostat": RiskTier.R1_LOCAL_REVERSIBLE,
    "skill.synthesize": RiskTier.R1_LOCAL_REVERSIBLE,
    # R2 External Reversible / Bounded
    "git.commit": RiskTier.R2_EXTERNAL_REVERSIBLE,
    "git.push_branch": RiskTier.R2_EXTERNAL_REVERSIBLE,
    "web.submit": RiskTier.R2_EXTERNAL_REVERSIBLE,
    "web.download": RiskTier.R2_EXTERNAL_REVERSIBLE,
    "calendar.invite": RiskTier.R2_EXTERNAL_REVERSIBLE,
    "shell.exec": RiskTier.R2_EXTERNAL_REVERSIBLE,
    # R3 Consequential
    "email.send": RiskTier.R3_CONSEQUENTIAL,
    "git.merge_main": RiskTier.R3_CONSEQUENTIAL,
    "fs.delete_permanent": RiskTier.R3_CONSEQUENTIAL,
    "device.appliance": RiskTier.R3_CONSEQUENTIAL,
    "device.camera": RiskTier.R3_CONSEQUENTIAL,
    "shell.exec_privileged": RiskTier.R3_CONSEQUENTIAL,
    # R4 Critical / Irreversible
    "finance.pay": RiskTier.R4_CRITICAL_IRREVERSIBLE,
    "finance.transfer": RiskTier.R4_CRITICAL_IRREVERSIBLE,
    "device.lock": RiskTier.R4_CRITICAL_IRREVERSIBLE,
    "device.unlock": RiskTier.R4_CRITICAL_IRREVERSIBLE,
    "device.alarm_disarm": RiskTier.R4_CRITICAL_IRREVERSIBLE,
    "device.garage": RiskTier.R4_CRITICAL_IRREVERSIBLE,
    "policy.modify": RiskTier.R4_CRITICAL_IRREVERSIBLE,
    "account.credentials": RiskTier.R4_CRITICAL_IRREVERSIBLE,
}

INJECTION_PHRASES = (
    "ignore previous instructions",
    "ignore all rules",
    "disregard previous",
    "system override",
    "you are now",
    "approve mandate",
    "disable safety",
    "send secret",
    "exfiltrate",
    "rm -rf /",
    "forward all bank",
)


class PolicyEngine:
    def __init__(
        self,
        kernel: SafetyKernelProtocol,
        store: Optional[StoreProtocol] = None,
        catalog_overrides: Optional[Dict[str, RiskTier]] = None,
    ) -> None:
        self.kernel = kernel
        self.store = store
        self.catalog = dict(DEFAULT_ACTION_CATALOG)
        if catalog_overrides:
            self.catalog.update(catalog_overrides)
        self.policy_hash = canonical_hash(self.catalog)[:16]

    def evaluate(self, request: PolicyRequest) -> AuthorizationDecision:
        if self.kernel.is_stopped():
            return AuthorizationDecision(
                allowed=False,
                effective_risk=RiskTier.R4_CRITICAL_IRREVERSIBLE,
                reason_code="ESTOP_ACTIVE",
                explanation="Emergency stop is active",
                policy_hash=self.policy_hash,
            )

        if request.action not in self.catalog:
            return AuthorizationDecision(
                allowed=False,
                effective_risk=RiskTier.R4_CRITICAL_IRREVERSIBLE,
                reason_code="UNKNOWN_ACTION",
                explanation=f"Action '{request.action}' is not in the approved catalog",
                policy_hash=self.policy_hash,
            )

        cat_risk = self.catalog[request.action]
        effective_risk = cat_risk if cat_risk.rank >= request.requested_risk.rank else request.requested_risk

        if request.data_class == DataClass.D4_SECRET:
            return AuthorizationDecision(
                allowed=False,
                effective_risk=effective_risk,
                reason_code="D4_SECRET_FORBIDDEN",
                explanation="D4 secrets are never allowed in model context or external tool args",
                policy_hash=self.policy_hash,
            )

        if request.data_class == DataClass.D3_RESTRICTED_LOCAL and request.target_provider != "local":
            has_d3_approval = False
            if request.approval_id and self.store:
                apr = self.store.get_approval(request.approval_id)
                if apr and apr.status == "APPROVED" and (apr.expires_at is None or apr.expires_at > utc_now()):
                    has_d3_approval = True
            if not has_d3_approval:
                return AuthorizationDecision(
                    allowed=False,
                    effective_risk=effective_risk,
                    requires_approval=True,
                    reason_code="D3_CLOUD_BLOCKED",
                    explanation="D3 restricted data requires local model/worker or explicit owner approval",
                    policy_hash=self.policy_hash,
                )

        if effective_risk == RiskTier.R4_CRITICAL_IRREVERSIBLE:
            if request.approval_id and self.store:
                apr = self.store.get_approval(request.approval_id)
                if (
                    apr
                    and apr.status == "APPROVED"
                    and apr.args_hash == canonical_hash(request.args)
                    and (apr.expires_at is None or apr.expires_at > utc_now())
                    and request.step_up_verified
                ):
                    return AuthorizationDecision(
                        allowed=True,
                        effective_risk=effective_risk,
                        reason_code="R4_STEP_UP_APPROVED",
                        explanation="R4 action approved with owner step-up verification",
                        policy_hash=self.policy_hash,
                    )
            return AuthorizationDecision(
                allowed=False,
                effective_risk=effective_risk,
                requires_approval=True,
                requires_step_up=True,
                reason_code="R4_REQUIRES_STEP_UP",
                explanation="R4 critical actions always require per-action human step-up approval",
                policy_hash=self.policy_hash,
            )

        if request.approval_id and self.store:
            apr = self.store.get_approval(request.approval_id)
            if (
                apr
                and apr.status == "APPROVED"
                and apr.args_hash == canonical_hash(request.args)
                and (apr.expires_at is None or apr.expires_at > utc_now())
                and (effective_risk.rank < 3 or request.step_up_verified)
            ):
                return AuthorizationDecision(
                    allowed=True,
                    effective_risk=effective_risk,
                    reason_code="EXPLICIT_APPROVAL_GRANTED",
                    explanation="Explicitly approved by owner",
                    policy_hash=self.policy_hash,
                )

        if request.mandate_id and self.store:
            m = self.store.get_mandate(request.mandate_id)
            if m and m.active and (m.expires_at is None or m.expires_at > utc_now()):
                domain_ok = m.domain in {request.domain, "*", "general"}
                risk_ok = effective_risk.rank <= m.max_risk_tier.rank
                action_ok = (not m.allowed_actions) or (request.action in m.allowed_actions)
                spend_ok = True
                if request.estimated_spend_usd > 0:
                    spend_ok = (
                        request.estimated_spend_usd <= m.per_action_spend_cap_usd
                        and (m.spent_today_usd + request.estimated_spend_usd) <= m.daily_spend_cap_usd
                    )
                recip_ok = True
                if "recipient" in request.args and m.allowed_recipients:
                    recip_ok = str(request.args["recipient"]) in m.allowed_recipients
                dom_allow_ok = True
                if "domain" in request.args and m.allowed_domains:
                    dom_allow_ok = str(request.args["domain"]) in m.allowed_domains
                path_ok = True
                if "path" in request.args and m.allowed_paths:
                    path_ok = any(str(request.args["path"]).startswith(p) for p in m.allowed_paths)

                if domain_ok and risk_ok and action_ok and spend_ok and recip_ok and dom_allow_ok and path_ok:
                    return AuthorizationDecision(
                        allowed=True,
                        effective_risk=effective_risk,
                        reason_code="MANDATE_AUTHORIZED",
                        explanation=f"Authorized by StandingMandate '{m.name}'",
                        policy_hash=self.policy_hash,
                    )
            return AuthorizationDecision(
                allowed=False,
                effective_risk=effective_risk,
                requires_approval=True,
                requires_step_up=(effective_risk.rank >= 3),
                reason_code="OUTSIDE_MANDATE_BOUNDS",
                explanation="Action exceeds StandingMandate constraints",
                policy_hash=self.policy_hash,
            )

        if effective_risk.rank <= request.autonomy_level.max_auto_risk:
            return AuthorizationDecision(
                allowed=True,
                effective_risk=effective_risk,
                reason_code="AUTONOMY_DIAL_ALLOWED",
                explanation=f"Allowed by autonomy dial {request.autonomy_level.value}",
                policy_hash=self.policy_hash,
            )

        return AuthorizationDecision(
            allowed=False,
            effective_risk=effective_risk,
            requires_approval=True,
            requires_step_up=(effective_risk.rank >= 3),
            reason_code="REQUIRES_APPROVAL",
            explanation=f"Risk {effective_risk.value} requires approval at {request.autonomy_level.value}",
            policy_hash=self.policy_hash,
        )

    def wrap_untrusted(self, content: str, source: str) -> str:
        clean = redact_secrets(content)
        h = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        return f'<untrusted_data source="{source}" sha256="{h}">\n{clean}\n</untrusted_data>'

    def scan_prompt_injection(self, content: str) -> List[str]:
        low = content.lower()
        found = [phrase for phrase in INJECTION_PHRASES if phrase in low]
        if any(zw in content for zw in ("\u200b", "\u200c", "\u200d", "\ufeff")):
            found.append("zero_width_obfuscation")
        return found
