import re
from urllib.parse import urlparse


def link_analysis(message):

    findings = []

    urls = re.findall(
        r'https?://[^\s]+',
        message
    )

    if not urls:
        return findings

    for url in urls:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        findings.append(
            f"A link was detected with the domain: {domain}"
        )

        suspicious_words = [
            "verify",
            "login",
            "secure",
            "update",
            "account",
            "reward",
            "bonus"
        ]

        if any(
            word in url.lower()
            for word in suspicious_words
        ):

            findings.append(
                "The link contains words commonly associated with account verification or credential-related requests."
            )

        if "@" in url:

            findings.append(
                "The URL contains an unusual '@' character."
            )

    return findings
