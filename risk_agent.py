def analyze_message(message):

    text = message.lower()
    risk_signals = []

    urgency_words = [
        "urgent",
        "immediately",
        "immediate",
        "within",
        "now",
        "last chance"
    ]

    threat_words = [
        "blocked",
        "suspended",
        "deactivated",
        "penalty",
        "disconnect"
    ]

    money_words = [
        "pay",
        "payment",
        "transfer",
        "upi",
        "bank account",
        "refund",
        "reward",
        "prize"
    ]

    for word in urgency_words:
        if word in text:
            risk_signals.append(
                f"Urgency language detected: '{word}'"
            )

    for word in threat_words:
        if word in text:
            risk_signals.append(
                f"Threat or pressure language detected: '{word}'"
            )

    for word in money_words:
        if word in text:
            risk_signals.append(
                f"Money-related language detected: '{word}'"
            )

    if "http://" in text or "https://" in text:
        risk_signals.append(
            "A web link was detected."
        )

    return risk_signals