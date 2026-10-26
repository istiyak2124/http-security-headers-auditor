from headers_auditor.models import Finding, Severity

def _get_header(
    headers: dict[str, str],
    name: str,
) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value

    return None


def check_x_content_type_options(
    headers: dict[str, str],
) -> list[Finding]:
    value = _get_header(headers, "X-Content-Type-Options")

    if value is None:
        return [
            Finding(
                header="X-Content-Type-Options",
                severity=Severity.MEDIUM,
                message="Security header is missing.",
                recommendation=(
                    "Set X-Content-Type-Options to nosniff."
                ),
            )
        ]

    if value.strip().lower() != "nosniff":
        return [
            Finding(
                header="X-Content-Type-Options",
                severity=Severity.MEDIUM,
                message="Security header has an unexpected value.",
                recommendation=(
                    "Set X-Content-Type-Options to nosniff."
                ),
            )
        ]

    return []



def check_x_frame_options(
    headers: dict[str, str],
) -> list[Finding]:
    value = _get_header(headers, "X-Frame-Options")

    if value is None:
        csp = _get_header(
            headers,
            "Content-Security-Policy",
        )

        if csp:
            for directive in csp.split(";"):
                parts = directive.strip().split(None, 1)

                if (
                    len(parts) == 2
                    and parts[0].lower() == "frame-ancestors"
                    and parts[1].strip()
                ):
                    return []

        return [
            Finding(
                header="X-Frame-Options",
                severity=Severity.MEDIUM,
                message="Security header is missing.",
                recommendation=(
                    "Set X-Frame-Options to DENY or SAMEORIGIN, "
                    "or configure an appropriate CSP frame-ancestors directive."
                ),
            )
        ]

    if value.strip().upper() not in {"DENY", "SAMEORIGIN"}:
        return [
            Finding(
                header="X-Frame-Options",
                severity=Severity.MEDIUM,
                message="Security header has an unexpected value.",
                recommendation=(
                    "Set X-Frame-Options to DENY or SAMEORIGIN."
                ),
            )
        ]

    return []



def check_hsts(
    headers: dict[str, str],
) -> list[Finding]:
    value = _get_header(headers, "Strict-Transport-Security")

    if value is None or not value.strip():
        return [
            Finding(
                header="Strict-Transport-Security",
                severity=Severity.HIGH,
                message="Security header is missing or empty.",
                recommendation=(
                    "Configure Strict-Transport-Security with an "
                    "appropriate max-age directive on HTTPS responses."
                ),
            )
        ]

    directives = [
        directive.strip()
        for directive in value.split(";")
        if directive.strip()
    ]

    max_age_values = [
        directive.split("=", 1)[1].strip()
        for directive in directives
        if directive.lower().startswith("max-age=")
    ]

    if (
        len(max_age_values) != 1
        or not max_age_values[0].isdigit()
        or int(max_age_values[0]) == 0
    ):
        return [
            Finding(
                header="Strict-Transport-Security",
                severity=Severity.HIGH,
                message=(
                    "Strict-Transport-Security has a missing, "
                    "duplicate, or invalid max-age directive."
                ),
                recommendation=(
                    "Set exactly one positive max-age value in "
                    "Strict-Transport-Security."
                ),
            )
        ]

    return []




def check_csp(
    headers: dict[str, str],
) -> list[Finding]:
    value = _get_header(headers, "Content-Security-Policy")

    if value is None or not value.strip():
        return [
            Finding(
                header="Content-Security-Policy",
                severity=Severity.HIGH,
                message="Security header is missing or empty.",
                recommendation=(
                    "Configure a Content-Security-Policy that "
                    "restricts resource sources appropriately."
                ),
            )
        ]

    directives = [
        directive.strip().lower()
        for directive in value.split(";")
        if directive.strip()
    ]

    if not directives:
        return [
            Finding(
                header="Content-Security-Policy",
                severity=Severity.HIGH,
                message="Security policy contains no directives.",
                recommendation=(
                    "Configure a Content-Security-Policy with "
                    "appropriate directives."
                ),
            )
        ]

    return []


def check_referrer_policy(
    headers: dict[str, str],
) -> list[Finding]:
    value = _get_header(headers, "Referrer-Policy")

    if value is None or not value.strip():
        return [
            Finding(
                header="Referrer-Policy",
                severity=Severity.MEDIUM,
                message="Security header is missing or empty.",
                recommendation=(
                    "Configure Referrer-Policy with an appropriate "
                    "value, such as strict-origin-when-cross-origin."
                ),
            )
        ]

    valid_policies = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }

    policies = [
        policy.strip().lower()
        for policy in value.split(",")
        if policy.strip()
    ]

    if not policies or policies[-1] not in valid_policies:
        return [
            Finding(
                header="Referrer-Policy",
                severity=Severity.MEDIUM,
                message="Security header has an unexpected value.",
                recommendation=(
                    "Use a recognized Referrer-Policy value, "
                    "such as strict-origin-when-cross-origin."
                ),
            )
        ]

    return []


def check_permissions_policy(
    headers: dict[str, str],
) -> list[Finding]:
    value = _get_header(headers, "Permissions-Policy")

    if value is None or not value.strip():
        return [
            Finding(
                header="Permissions-Policy",
                severity=Severity.LOW,
                message="Security header is missing or empty.",
                recommendation=(
                    "Configure Permissions-Policy to restrict "
                    "browser features that the website does not need."
                ),
            )
        ]

    return []