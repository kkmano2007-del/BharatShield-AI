def scam_pattern_analysis(
    social_results,
    financial_results,
    link_results,
    identity_results,
    message
):

    findings = []

    text = message.lower()

    urgency_present = any(
        word in text
        for word in [
            "urgent",
            "immediately",
            "within",
            "now"
        ]
    )

    if urgency_present and financial_results:
        findings.append(
            "Pattern detected: Urgency combined with a financial request."
        )

    action_present = any(
        word in text
        for word in [
            "click",
            "verify",
            "reply",
            "pay",
            "transfer",
            "enter"
        ]
    )

    if identity_results and action_present:
        findings.append(
            "Pattern detected: A claimed identity is combined with an action request."
        )

    threat_present = any(
        word in text
        for word in [
            "blocked",
            "suspended",
            "penalty",
            "disconnect"
        ]
    )

    if threat_present and "verify" in text:
        findings.append(
            "Pattern detected: A threat is combined with a verification request."
        )

    sensitive_present = any(
        word in text
        for word in [
            "otp",
            "pin",
            "cvv",
            "password"
        ]
    )

    if sensitive_present and (
        identity_results
        or link_results
    ):
        findings.append(
            "Pattern detected: A claimed identity or external link is combined "
            "with a sensitive-information request."
        )

    return findings