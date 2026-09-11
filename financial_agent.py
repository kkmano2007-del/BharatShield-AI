def financial_risk_analysis(message):

    text = message.lower()
    findings = []

    if any(
        word in text
        for word in [
            "pay",
            "payment",
            "transfer",
            "upi",
            "money",
            "refund",
            "bank account",
            "reward",
            "prize"
        ]
    ):
        findings.append(
            "The message involves a possible financial transaction or monetary claim."
        )

    if any(
        word in text
        for word in [
            "otp",
            "pin",
            "cvv",
            "password"
        ]
    ):
        findings.append(
            "The message refers to sensitive financial or account information."
        )

    return findings