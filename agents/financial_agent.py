def financial_risk_analysis(message):

    text = message.lower()

    findings = []

    sensitive_keywords = {
        "otp": "The message references an OTP, which should never be shared with an untrusted party.",
        "pin": "The message references a PIN or sensitive authentication information.",
        "password": "The message references a password or sensitive authentication information.",
        "cvv": "The message references CVV information.",
        "login details": "The message requests or references login details.",
        "login credentials": "The message requests or references login credentials.",
        "account details": "The message requests or references account details."
    }

    for keyword, explanation in sensitive_keywords.items():

        if keyword in text:
            findings.append(explanation)

    financial_words = [
        "bank",
        "payment",
        "money",
        "upi",
        "transfer",
        "cashback",
        "reward",
        "prize"
    ]

    if any(word in text for word in financial_words):

        findings.append(
            "Financial or account-related language was detected and should be independently verified."
        )

    return findings
