"""Chat-based reporting for M365 security posture.

The :class:`SecurityReporter` produces human-readable reports from
:class:`~agent.m365.security.SecurityPosture` objects.  It also provides
a simple natural-language query interface so the Foundry agent can answer
questions such as:

* "What is the security score for tenant X?"
* "Show me all critical findings."
* "List high severity findings for tenant Y."
* "How many users are missing MFA?"
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ..m365.security import SecurityPosture, Severity


class SecurityReporter:
    """Generates security posture reports and handles chat queries."""

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_summary(self, posture: SecurityPosture) -> str:
        """Return a concise Markdown summary for *posture*."""
        lines: List[str] = []
        lines.append(f"## Security Posture Report – {posture.tenant_name}")
        lines.append(
            f"*Generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*\n"
        )

        # Secure Score
        if posture.score_percentage is not None:
            bar = _score_bar(posture.score_percentage)
            lines.append(
                f"**Secure Score:** {posture.secure_score:.0f} / "
                f"{posture.secure_score_max:.0f} "
                f"({posture.score_percentage}%)  {bar}"
            )
        else:
            lines.append("**Secure Score:** Not available")

        # Findings summary
        by_sev = posture.findings_by_severity
        lines.append("\n### Findings Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in Severity:
            count = len(by_sev[sev.value])
            emoji = _severity_emoji(sev)
            lines.append(f"| {emoji} {sev.value.capitalize()} | {count} |")

        # Critical & high findings detail
        critical_high = (
            by_sev[Severity.CRITICAL.value] + by_sev[Severity.HIGH.value]
        )
        if critical_high:
            lines.append("\n### Critical & High Findings\n")
            for f in critical_high:
                emoji = _severity_emoji(f.severity)
                lines.append(f"- {emoji} **[{f.rule_id}]** {f.title}")
                lines.append(f"  - *Recommendation:* {f.recommendation}")

        lines.append("\n---")
        return "\n".join(lines)

    def generate_full_report(self, posture: SecurityPosture) -> str:
        """Return a detailed Markdown report listing all findings."""
        lines: List[str] = [self.generate_summary(posture)]
        lines.append("\n### All Findings\n")

        if not posture.findings:
            lines.append("✅ No findings – tenant meets all checked controls.")
            return "\n".join(lines)

        for f in sorted(posture.findings, key=lambda x: _severity_order(x.severity)):
            emoji = _severity_emoji(f.severity)
            lines.append(
                f"#### {emoji} [{f.rule_id}] {f.title}\n"
                f"- **Severity:** {f.severity.value.capitalize()}\n"
                f"- **Resource:** {f.resource_type} / {f.resource_name}\n"
                f"- **Description:** {f.description}\n"
                f"- **Recommendation:** {f.recommendation}\n"
                f"- **Auto-remediation:** {'Available' if f.remediation_available else 'Not available'}\n"
            )

        return "\n".join(lines)

    def generate_multi_tenant_report(
        self, postures: Dict[str, SecurityPosture]
    ) -> str:
        """Return a Markdown summary comparing multiple tenant postures."""
        lines: List[str] = []
        lines.append("## Multi-Tenant Security Posture Report")
        lines.append(
            f"*Generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*\n"
        )
        lines.append("| Tenant | Score | Critical | High | Medium | Low |")
        lines.append("|--------|-------|----------|------|--------|-----|")
        for tenant_id, posture in postures.items():
            by_sev = posture.findings_by_severity
            score_str = (
                f"{posture.score_percentage}%"
                if posture.score_percentage is not None
                else "N/A"
            )
            lines.append(
                f"| {posture.tenant_name} | {score_str} "
                f"| {len(by_sev[Severity.CRITICAL.value])} "
                f"| {len(by_sev[Severity.HIGH.value])} "
                f"| {len(by_sev[Severity.MEDIUM.value])} "
                f"| {len(by_sev[Severity.LOW.value])} |"
            )

        lines.append("")
        for posture in postures.values():
            lines.append(self.generate_summary(posture))

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Chat / natural language query interface
    # ------------------------------------------------------------------

    def handle_query(
        self,
        query: str,
        postures: Dict[str, SecurityPosture],
    ) -> str:
        """Process a natural-language chat query and return a response."""
        q = query.strip().lower()

        # ---- Score queries -----------------------------------------------
        if re.search(r"score", q):
            tenant_name = _extract_tenant_name(q)
            posture = _find_posture(tenant_name, postures)
            if posture is None:
                return self._list_tenants(postures)
            if posture.score_percentage is not None:
                return (
                    f"🔒 **{posture.tenant_name}** has a Secure Score of "
                    f"**{posture.score_percentage}%** "
                    f"({posture.secure_score:.0f} / {posture.secure_score_max:.0f})."
                )
            return f"Secure Score data is not available for **{posture.tenant_name}**."

        # ---- Findings queries --------------------------------------------
        match = re.search(r"(critical|high|medium|low|informational)", q)
        severity_filter: Optional[Severity] = None
        if match:
            severity_filter = Severity(match.group(1))

        if re.search(r"find|issue|alert|problem|vulnerabilit", q):
            tenant_name = _extract_tenant_name(q)
            posture = _find_posture(tenant_name, postures)
            if posture is None:
                return self._list_tenants(postures)
            findings = posture.findings
            if severity_filter:
                findings = [
                    f for f in findings if f.severity == severity_filter
                ]
            if not findings:
                return (
                    f"✅ No {'`' + severity_filter.value + '`' if severity_filter else ''} "
                    f"findings for **{posture.tenant_name}**."
                )
            result = (
                f"**{posture.tenant_name}** has "
                f"**{len(findings)}** "
                f"{'`' + severity_filter.value + '`' if severity_filter else ''} "
                f"finding(s):\n\n"
            )
            for f in findings[:10]:
                emoji = _severity_emoji(f.severity)
                result += f"- {emoji} **[{f.rule_id}]** {f.title}\n"
            if len(findings) > 10:
                result += f"\n*…and {len(findings) - 10} more.*"
            return result

        # ---- MFA queries -------------------------------------------------
        if re.search(r"mfa|multi.factor|multifactor", q):
            tenant_name = _extract_tenant_name(q)
            posture = _find_posture(tenant_name, postures)
            if posture is None:
                return self._list_tenants(postures)
            mfa_findings = [f for f in posture.findings if f.category == "mfa"]
            if not mfa_findings:
                return f"✅ No MFA-related findings for **{posture.tenant_name}**."
            return (
                f"**{posture.tenant_name}** has {len(mfa_findings)} MFA-related finding(s):\n\n"
                + "\n".join(
                    f"- {_severity_emoji(f.severity)} **[{f.rule_id}]** {f.title}"
                    for f in mfa_findings
                )
            )

        # ---- Summary query -----------------------------------------------
        if re.search(r"summar|report|overview|status", q):
            if len(postures) == 1:
                return self.generate_summary(next(iter(postures.values())))
            tenant_name = _extract_tenant_name(q)
            posture = _find_posture(tenant_name, postures)
            if posture:
                return self.generate_summary(posture)
            return self.generate_multi_tenant_report(postures)

        # ---- Tenant list query -------------------------------------------
        if re.search(r"tenant|which|list", q):
            return self._list_tenants(postures)

        # ---- Fallback ----------------------------------------------------
        return (
            "I can help with M365 security posture. Try asking:\n"
            "- *What is the security score for tenant X?*\n"
            "- *Show me critical findings.*\n"
            "- *List high severity findings for tenant Y.*\n"
            "- *How many users are missing MFA?*\n"
            "- *Give me a summary report.*"
        )

    def _list_tenants(self, postures: Dict[str, SecurityPosture]) -> str:
        if not postures:
            return "No tenant assessments are available yet. Run an assessment first."
        lines = ["**Monitored tenants:**\n"]
        for posture in postures.values():
            score_str = (
                f"{posture.score_percentage}%"
                if posture.score_percentage is not None
                else "N/A"
            )
            lines.append(
                f"- **{posture.tenant_name}** (`{posture.tenant_id}`) – "
                f"Score: {score_str}, Findings: {len(posture.findings)}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _score_bar(percentage: float, width: int = 10) -> str:
    filled = round(percentage / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"`[{bar}]`"


def _severity_emoji(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🟢",
        Severity.INFORMATIONAL: "🔵",
    }.get(severity, "⚪")


def _severity_order(severity: Severity) -> int:
    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFORMATIONAL: 4,
    }.get(severity, 99)


def _extract_tenant_name(query: str) -> Optional[str]:
    """Extract a tenant name hint from a natural-language query."""
    match = re.search(r"(?:for|tenant|of)\s+['\"]?([a-z0-9\-\. ]+)['\"]?", query)
    if match:
        return match.group(1).strip()
    return None


def _find_posture(
    name_hint: Optional[str],
    postures: Dict[str, SecurityPosture],
) -> Optional[SecurityPosture]:
    """Find a posture by tenant name/id hint; return first if hint is None."""
    if not postures:
        return None
    if name_hint is None:
        return next(iter(postures.values()))
    hint_lower = name_hint.lower()
    for posture in postures.values():
        if hint_lower in posture.tenant_name.lower() or hint_lower in posture.tenant_id.lower():
            return posture
    return None
