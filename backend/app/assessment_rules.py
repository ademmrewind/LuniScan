import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel

from app.monitor_engine import Outcome, ResponseEvidence

Severity = Literal["informational", "low", "medium", "high"]
Evaluation = Literal["pass", "finding", "inconclusive", "not_applicable"]


@dataclass(frozen=True)
class Rule:
    code: str
    title: str
    recommendation: str


class Observation(BaseModel):
    rule: str
    title: str
    category: Literal["http_header", "tls"]
    evaluation: Evaluation
    severity: Severity | None = None
    present: bool | None = None
    evidence: str
    explanation: str
    recommendation: str


HEADERS = {
    rule.code: rule
    for rule in (
        Rule(
            "strict-transport-security",
            "Strict-Transport-Security",
            "Set an appropriate positive max-age after verifying reliable HTTPS coverage.",
        ),
        Rule(
            "content-security-policy",
            "Content-Security-Policy",
            "Review script restrictions and gradually deploy an enforcing policy suited to the application.",
        ),
        Rule(
            "x-content-type-options",
            "X-Content-Type-Options",
            "Send X-Content-Type-Options: nosniff and correct Content-Type headers.",
        ),
        Rule(
            "referrer-policy",
            "Referrer-Policy",
            "Choose a referrer policy appropriate to the application, such as strict-origin-when-cross-origin.",
        ),
        Rule(
            "x-frame-options",
            "X-Frame-Options",
            "For pages needing framing restrictions, use CSP frame-ancestors or a supported X-Frame-Options value.",
        ),
        Rule(
            "permissions-policy",
            "Permissions-Policy",
            "Limit browser features to origins that require them.",
        ),
    )
}
TLS = {
    rule.code: rule
    for rule in (
        Rule(
            "tls_verification",
            "TLS certificate verification",
            "Deploy a trusted certificate chain matching the approved service name or IP.",
        ),
        Rule(
            "tls_expiration",
            "TLS certificate expiration",
            "Renew and deploy the certificate before its expiry.",
        ),
        Rule(
            "tls_protocol",
            "Negotiated TLS protocol",
            "Configure modern TLS versions and verify with a normal client connection.",
        ),
    )
}


def output(
    rule: Rule,
    evaluation: Evaluation,
    evidence: str,
    explanation: str,
    severity: Severity | None = None,
    present: bool | None = None,
) -> Observation:
    return Observation(
        rule=rule.code,
        title=rule.title,
        category="tls" if rule.code in TLS else "http_header",
        evaluation=evaluation,
        severity=severity,
        present=present,
        evidence=evidence,
        explanation=explanation,
        recommendation=rule.recommendation,
    )


TOKEN = re.compile(r"^[a-z][a-z0-9-]{0,40}$")
REFERRER_VALUES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


def effective_csp(value: str) -> dict[str, list[str]]:
    directives = {}
    for segment in value.split(";"):
        parts = segment.split()
        if parts and TOKEN.fullmatch(parts[0].lower()):
            directives.setdefault(
                parts[0].lower(), [token.lower() for token in parts[1:]]
            )
    return directives


def header_rules(
    protocol: str, outcome: Outcome, evidence: ResponseEvidence
) -> list[Observation]:
    headers = evidence.headers
    csp_values = headers.get("content-security-policy", [])
    policies = [effective_csp(value) for value in csp_values]
    restrictive_frame = any(
        p.get("frame-ancestors")
        and all(token in {"'none'", "'self'"} for token in p["frame-ancestors"])
        for p in policies
    )
    rows = []
    for name, rule in HEADERS.items():
        values = headers.get(name, [])
        present = bool(values)
        if name == "strict-transport-security" and protocol != "https":
            rows.append(
                output(
                    rule,
                    "not_applicable",
                    "Plain HTTP",
                    "HSTS is applied only from a secure response.",
                    present=present if outcome.http_status else None,
                )
            )
            continue
        if outcome.http_status is None or not 200 <= outcome.http_status < 300:
            summary = (
                f"HTTP {outcome.http_status}"
                if outcome.http_status is not None
                else "No HTTP response"
            )
            rows.append(
                output(
                    rule,
                    "inconclusive",
                    summary,
                    "A successful endpoint response is needed to assess this header.",
                    present=present if outcome.http_status is not None else None,
                )
            )
            continue
        if name == "x-frame-options" and restrictive_frame:
            rows.append(
                output(
                    rule,
                    "pass",
                    "CSP frame-ancestors restricts framing",
                    "An enforcing CSP policy provides framing protection for this response.",
                    present=present,
                )
            )
            continue
        if not present:
            severity = (
                "low"
                if name in {"strict-transport-security", "x-content-type-options"}
                else "informational"
            )
            rows.append(
                output(
                    rule,
                    "finding",
                    "Header absent",
                    "This response lacks an explicit defense. Applicability depends on the endpoint and client.",
                    severity,
                    False,
                )
            )
            continue
        value = values[0].strip().lower()
        if name == "strict-transport-security":
            age_fields = [
                part.split("=", 1)[1].strip()
                for part in value.split(";")
                if part.split("=", 1)[0].strip() == "max-age" and "=" in part
            ]
            valid = len(age_fields) == 1 and bool(
                re.fullmatch(r"[0-9]{1,12}", age_fields[0])
            )
            passed = valid and int(age_fields[0]) > 0
            summary = (
                f"max-age={int(age_fields[0])}"
                if valid
                else "Missing or invalid max-age"
            )
            explanation = (
                "A positive max-age requests HTTPS-only access in supporting browsers."
                if passed
                else "HSTS is disabled or cannot be applied reliably."
            )
        elif name == "content-security-policy":
            summary = f"{len(policies)} enforcing policy header(s)"
            if len(policies) != 1 or "," in value or not policies[0]:
                rows.append(
                    output(
                        rule,
                        "inconclusive",
                        summary,
                        "Combined, multiple or unparsed policies require manual interpretation.",
                        present=True,
                    )
                )
                continue
            policy = policies[0]
            sources = policy.get("script-src", policy.get("default-src", []))
            flags = sorted(set(sources) & {"*", "'unsafe-inline'", "'unsafe-eval'"})
            inline_override = any(
                token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                for token in sources
            )
            if inline_override and "'unsafe-inline'" in flags:
                flags.remove("'unsafe-inline'")
            passed = bool(sources) and not flags
            summary = "Script sources: " + (
                ", ".join(flags)
                if flags
                else "restrictions observed"
                if sources
                else "no script/default restriction"
            )
            explanation = "This is a limited check of common script source directives. Review the effective policy for this application."
        elif name == "x-content-type-options":
            passed = value == "nosniff" and len(values) == 1
            summary = "nosniff" if passed else "Unexpected directive"
            explanation = (
                "nosniff tells supporting browsers to respect the declared media type."
            )
        elif name == "referrer-policy":
            recognized = [
                item.strip()
                for row in values
                for item in row.lower().split(",")
                if item.strip() in REFERRER_VALUES
            ]
            policy = recognized[-1] if recognized else None
            passed = policy is not None and policy not in {
                "unsafe-url",
                "no-referrer-when-downgrade",
            }
            summary = policy or "No recognized directive"
            explanation = "A permissive policy can disclose referrer details to other destinations."
        elif name == "x-frame-options":
            passed = len(values) == 1 and value in {"deny", "sameorigin"}
            summary = (
                value.upper() if passed else "Unsupported or conflicting directive"
            )
            explanation = "Use supported framing controls where the response is intended for browser rendering."
        else:
            wildcard = bool(re.search(r"=\s*\*", value))
            recognizable = bool(re.search(r"[a-z][a-z0-9-]*\s*=", value))
            if len(values) != 1 or not recognizable:
                rows.append(
                    output(
                        rule,
                        "inconclusive",
                        "Directive structure not established",
                        "Review the effective policy in a browser.",
                        present=True,
                    )
                )
                continue
            passed = not wildcard
            summary = (
                "Wildcard feature allowlist"
                if wildcard
                else "Feature directives observed"
            )
            explanation = "Feature allowlists should reflect the application's browser requirements."
        rows.append(
            output(
                rule,
                "pass" if passed else "finding",
                summary,
                explanation,
                None if passed else "low",
                True,
            )
        )
    return rows


def tls_rules(
    protocol: str, outcome: Outcome, evidence: ResponseEvidence
) -> list[Observation]:
    if protocol != "https":
        return [
            output(
                rule,
                "not_applicable",
                "Plain HTTP",
                "This profile does not negotiate TLS.",
            )
            for rule in TLS.values()
        ]
    cert = outcome.certificate
    verification, expiry, negotiated = TLS.values()
    rows = []
    if cert is not None and cert.verified is False:
        rows.append(
            output(
                verification,
                "finding",
                cert.state.replace("_", " "),
                "The default verifier rejected the certificate or endpoint identity.",
                "medium",
            )
        )
    elif cert is not None and cert.verified and cert.hostname_valid:
        rows.append(
            output(
                verification,
                "pass",
                "Trust chain and endpoint identity verified",
                "The certificate passed the verifier for the approved endpoint.",
            )
        )
    else:
        rows.append(
            output(
                verification,
                "inconclusive",
                "No verification result",
                "The handshake did not provide a verification result.",
            )
        )
    if cert and cert.state in {"expiring_soon", "expired"}:
        summary = (
            cert.expires_at.isoformat()
            if cert.expires_at
            else cert.state.replace("_", " ")
        )
        rows.append(
            output(
                expiry,
                "finding",
                summary,
                "Certificate expiry may disrupt verified clients.",
                "medium" if cert.state == "expired" else "low",
            )
        )
    elif cert and cert.verified and cert.state == "valid":
        rows.append(
            output(
                expiry,
                "pass",
                f"{cert.days_remaining} days remaining",
                "The verified certificate is outside the configured warning window.",
            )
        )
    else:
        rows.append(
            output(
                expiry,
                "inconclusive",
                "Validity period unavailable",
                "There is insufficient certificate information to assess expiry.",
            )
        )
    version = evidence.tls_version
    if version in {"TLSv1.2", "TLSv1.3", "TLSv1", "TLSv1.1", "SSLv3"}:
        cipher = evidence.tls_cipher or ""
        safe_cipher = (
            cipher if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", cipher) else "unavailable"
        )
        legacy = version not in {"TLSv1.2", "TLSv1.3"}
        rows.append(
            output(
                negotiated,
                "finding" if legacy else "pass",
                f"{version} / {safe_cipher}",
                "This is the observed negotiation. Other enabled protocols and ciphers were not enumerated.",
                "medium" if legacy else None,
            )
        )
    else:
        rows.append(
            output(
                negotiated,
                "inconclusive",
                "No supported negotiation observed",
                "Protocol and cipher details were unavailable.",
            )
        )
    return rows
