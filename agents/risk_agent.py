def analyze_message(message):

    text = message.lower()

    findings = []

    risk_keywords = {
        "urgent": "Urgency language was detected.",
        "immediately": "Pressure to act immediately was detected.",
        "immediate": "Immediate action is being requested.",
        "otp": "The message requests or references an OTP.",
        "password": "The message references a password.",
        "pin": "The message references a PIN.",
        "login": "The message references login information.",
        "credentials": "The message references account credentials.",
        "suspended": "A possible account suspension threat was detected.",
        "blocked": "A possible account blocking threat was detected.",
        "verify": "The message requests verification.",
        "reward": "A reward or incentive was mentioned.",
        "prize": "A prize-related claim was detected."
    }

    for keyword, explanation in risk_keywords.items():

        if keyword in text:
            findings.append(explanation)

    return findings
