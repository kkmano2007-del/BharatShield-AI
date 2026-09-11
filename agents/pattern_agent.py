def scam_pattern_analysis(
    social_results,
    financial_results,
    link_results,
    identity_results,
    message
):

    findings = []

    text = message.lower()

    # Urgency + sensitive information

    urgency_words = [
        "urgent",
        "immediately",
        "immediate",
        "now",
        "today"
    ]

    sensitive_words = [
        "otp",
        "password",
        "pin",
        "cvv",
        "credentials",
        "login details"
    ]

    urgency_found = any(
        word in text
        for word in urgency_words
    )

    sensitive_found = any(
        word in text
        for word in sensitive_words
    )

    if urgency_found and sensitive_found:

        findings.append(
            "A concerning combination of urgency and a request for sensitive information was detected."
        )

    # Threat + sensitive information

    threat_words = [
        "suspended",
        "blocked",
        "restricted",
        "deactivated"
    ]

    threat_found = any(
        word in text
        for word in threat_words
    )

    if threat_found and sensitive_found:

        findings.append(
            "A concerning combination of an account-related threat and sensitive information request was detected."
        )

    # Identity + sensitive request

    if identity_results and sensitive_found:

        findings.append(
            "A recognizable organization is referenced alongside a request for sensitive information."
        )

    # Link + sensitive request

    if link_results and sensitive_found:

        findings.append(
            "A link appears alongside a request for sensitive information."
        )

    # Multiple agents detect concerns

    active_agents = sum([
        bool(social_results),
        bool(financial_results),
        bool(link_results),
        bool(identity_results)
    ])

    if active_agents >= 3:

        findings.append(
            "Multiple independent investigation agents detected potentially concerning indicators."
        )

    return findings
