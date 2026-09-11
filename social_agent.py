def social_engineering_analysis(message):

    text = message.lower()
    findings = []

    if any(
        word in text
        for word in [
            "urgent",
            "immediately",
            "within",
            "now",
            "last chance"
        ]
    ):
        findings.append(
            "Artificial urgency may be encouraging rushed decisions."
        )

    if any(
        word in text
        for word in [
            "blocked",
            "suspended",
            "disconnect",
            "penalty"
        ]
    ):
        findings.append(
            "Fear or threat-based language was detected."
        )

    if any(
        word in text
        for word in [
            "click",
            "pay",
            "transfer",
            "reply",
            "verify",
            "enter"
        ]
    ):
        findings.append(
            "The message appears to request an action from the recipient."
        )

    return findings