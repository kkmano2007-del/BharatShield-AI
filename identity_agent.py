def identity_analysis(message):

    text = message.lower()

    organizations = {
        "sbi": "State Bank of India (SBI)",
        "hdfc": "HDFC Bank",
        "icici": "ICICI Bank",
        "amazon": "Amazon",
        "flipkart": "Flipkart",
        "google": "Google",
        "instagram": "Instagram",
        "whatsapp": "WhatsApp",
        "microsoft": "Microsoft",
        "government": "Government-related identity",
        "police": "Police-related identity"
    }

    identities = []

    for keyword, organization in organizations.items():

        if keyword in text:
            identities.append(
                organization
            )

    return identities