import re
from urllib.parse import urlparse


# ============================================================
# M1 CONTENT RULES
# ============================================================

URGENCY_TERMS = [
    "urgent",
    "immediately",
    "act now",
    "action required",
    "within 24 hours",
    "limited time",
    "last warning",
    "final warning",
]

CREDENTIAL_TERMS = [
    "password",
    "passcode",
    "otp",
    "one time password",
    "login",
    "log in",
    "verify your account",
    "confirm your identity",
    "credentials",
]

PAYMENT_TERMS = [
    "payment",
    "pay now",
    "invoice",
    "refund",
    "bank account",
    "credit card",
    "debit card",
    "transfer money",
    "wire transfer",
]

SUSPENSION_TERMS = [
    "account suspended",
    "account locked",
    "account will be closed",
    "account terminated",
    "access will be revoked",
]

IMPERSONATION_TERMS = [
    "customer support",
    "security team",
    "administrator",
    "admin team",
    "it support",
    "bank support",
    "official support",
]


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text):

    if not text:
        return []

    return re.findall(
        r"https?://[^\s<>\"]+|www\.[^\s<>\"]+",
        text,
        flags=re.IGNORECASE
    )


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_urls(urls):

    indicators = []

    suspicious_count = 0

    for url in urls:

        clean_url = url.rstrip(
            ".,);]>\"'"
        )

        try:
            parsed = urlparse(
                clean_url
            )

            domain = (
                parsed.netloc
                .lower()
                .split("@")[-1]
                .split(":")[0]
            )

            # IP address instead of domain
            if re.fullmatch(
                r"\d{1,3}(?:\.\d{1,3}){3}",
                domain
            ):
                indicators.append(
                    "URL uses an IP address instead of a domain"
                )

                suspicious_count += 1

            # URL contains @
            if "@" in clean_url:

                indicators.append(
                    "URL contains an @ symbol"
                )

                suspicious_count += 1

            # Suspicious URL words
            suspicious_words = [
                "login",
                "verify",
                "update",
                "secure",
                "account",
                "password",
                "confirm",
                "wallet",
                "payment",
            ]

            for word in suspicious_words:

                if word in clean_url.lower():

                    suspicious_count += 1

                    break

        except Exception:

            indicators.append(
                "Unable to fully parse a URL"
            )

    return suspicious_count, indicators


# ============================================================
# TERM ANALYSIS
# ============================================================

def count_terms(
    text,
    terms
):

    text = text.lower()

    matches = []

    for term in terms:

        if term in text:

            matches.append(term)

    return matches


# ============================================================
# MAIN RULE ENGINE
# ============================================================

def analyze_content(
    subject="",
    body=""
):

    subject = subject or ""
    body = body or ""

    combined_text = (
        subject
        + "\n"
        + body
    )

    combined_lower = combined_text.lower()

    findings = []
    categories = []

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    urgency_matches = count_terms(
        combined_lower,
        URGENCY_TERMS
    )

    if urgency_matches:

        findings.append({
            "rule_id": "R001",
            "category": "urgency",
            "severity": "medium",
            "description": (
                "Urgency or pressure language detected"
            ),
            "matches": urgency_matches,
        })

        categories.append(
            "urgency"
        )

    # --------------------------------------------------------
    # Credential harvesting
    # --------------------------------------------------------

    credential_matches = count_terms(
        combined_lower,
        CREDENTIAL_TERMS
    )

    if credential_matches:

        findings.append({
            "rule_id": "R002",
            "category": "credential_request",
            "severity": "high",
            "description": (
                "Credential or account-verification "
                "language detected"
            ),
            "matches": credential_matches,
        })

        categories.append(
            "credential_request"
        )

    # --------------------------------------------------------
    # Payment
    # --------------------------------------------------------

    payment_matches = count_terms(
        combined_lower,
        PAYMENT_TERMS
    )

    if payment_matches:

        findings.append({
            "rule_id": "R003",
            "category": "payment_request",
            "severity": "high",
            "description": (
                "Payment or financial-request "
                "language detected"
            ),
            "matches": payment_matches,
        })

        categories.append(
            "payment_request"
        )

    # --------------------------------------------------------
    # Account suspension
    # --------------------------------------------------------

    suspension_matches = count_terms(
        combined_lower,
        SUSPENSION_TERMS
    )

    if suspension_matches:

        findings.append({
            "rule_id": "R004",
            "category": "account_suspension",
            "severity": "high",
            "description": (
                "Account suspension or closure "
                "language detected"
            ),
            "matches": suspension_matches,
        })

        categories.append(
            "account_suspension"
        )

    # --------------------------------------------------------
    # Impersonation
    # --------------------------------------------------------

    impersonation_matches = count_terms(
        combined_lower,
        IMPERSONATION_TERMS
    )

    if impersonation_matches:

        findings.append({
            "rule_id": "R005",
            "category": "impersonation",
            "severity": "medium",
            "description": (
                "Potential organization/support "
                "impersonation language detected"
            ),
            "matches": impersonation_matches,
        })

        categories.append(
            "impersonation"
        )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = extract_urls(
        combined_text
    )

    url_count = len(urls)

    suspicious_url_count, url_findings = (
        analyze_urls(urls)
    )

    if url_count > 0:

        findings.append({
            "rule_id": "R006",
            "category": "url_presence",
            "severity": "low",
            "description": (
                f"{url_count} URL(s) detected"
            ),
            "matches": urls,
        })

    if suspicious_url_count > 0:

        findings.append({
            "rule_id": "R007",
            "category": "suspicious_url",
            "severity": "high",
            "description": (
                "Potentially suspicious URL pattern detected"
            ),
            "matches": url_findings,
        })

        categories.append(
            "suspicious_url"
        )

    # --------------------------------------------------------
    # Excessive links
    # --------------------------------------------------------

    if url_count >= 5:

        findings.append({
            "rule_id": "R008",
            "category": "many_urls",
            "severity": "medium",
            "description": (
                "Email contains an unusually high "
                "number of URLs"
            ),
            "matches": [str(url_count)],
        })

        categories.append(
            "many_urls"
        )

    # --------------------------------------------------------
    # Overall rule score
    # --------------------------------------------------------

    score = 0

    for finding in findings:

        severity = finding[
            "severity"
        ]

        if severity == "high":
            score += 20

        elif severity == "medium":
            score += 10

        else:
            score += 3

    score = min(
        score,
        100
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    if not findings:

        summary = (
            "No major content-based security "
            "indicator detected."
        )

    else:

        summary = (
            f"{len(findings)} content-based "
            f"indicator(s) detected."
        )

    return {
        "rule_score": score,
        "summary": summary,
        "categories": list(
            dict.fromkeys(categories)
        ),
        "findings": findings,
        "urls": urls,
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_subject = (
        "URGENT: Your account will be suspended"
    )

    test_body = """
    Your account requires immediate verification.

    Please login and confirm your password:
    http://192.168.1.10/verify

    Failure to complete this process may result
    in account suspension.

    """

    result = analyze_content(
        subject=test_subject,
        body=test_body
    )

    print("\nM1 RULE ENGINE TEST")
    print("=" * 60)

    print(
        "Rule Score:",
        result["rule_score"]
    )

    print(
        "Categories:",
        result["categories"]
    )

    print(
        "Summary:",
        result["summary"]
    )

    print("\nFindings:")

    for finding in result["findings"]:

        print(
            f"- {finding['rule_id']}: "
            f"{finding['description']}"
        )