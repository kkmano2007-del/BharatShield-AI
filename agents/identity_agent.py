def identity_analysis(message):

    text = message.lower()

    identities = []

    organizations = {
        "sbi": "State Bank of India (SBI)",
        "state bank of india": "State Bank of India (SBI)",
        "hdfc": "HDFC Bank",
        "icici": "ICICI Bank",
        "amazon": "Amazon",
        "flipkart": "Flipkart",
        "google": "Google",
        "instagram": "Instagram",
        "whatsapp": "WhatsApp",
        "microsoft": "Microsoft"
    }

    for keyword, organization in organizations.items():

        if keyword in text and organization not in identities:

            identities.append(
                organization
            )

    return identities
