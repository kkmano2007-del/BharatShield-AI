def social_engineering_analysis(message):

    text = message.lower()

    findings = []

    urgency_words = [
        "urgent",
        "immediately",
        "immediate",
        "now",
        "today",
        "last chance"
    ]

    if any(word in text for word in urgency_words):

        findings.append(
            "Possible artificial urgency or pressure to act quickly was detected."
        )

    fear_words = [
        "suspended",
        "blocked",
        "restricted",
        "deactivated",
        "penalty",
        "failure"
    ]

    if any(word in text for word in fear_words):

        findings.append(
            "Possible fear or threat-based pressure was detected."
        )

    action_words = [
        "click",
        "verify",
        "reply",
        "send",
        "provide"
    ]

    if any(word in text for word in action_words):

        findings.append(
            "The sender appears to be encouraging the recipient to take a specific action."
        )

    return findings
