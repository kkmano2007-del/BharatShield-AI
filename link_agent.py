import re
from urllib.parse import urlparse


def link_analysis(message):

    findings = []

    urls = re.findall(
        r'https?://[^\s]+',
        message
    )

    for url in urls:

        parsed_url = urlparse(url)

        domain = (
            parsed_url.netloc
            .lower()
        )

        findings.append(
            f"Detected link domain: {domain}"
        )

        if "@" in url:
            findings.append(
                "The link contains an unusual '@' character."
            )

        if len(domain) > 40:
            findings.append(
                "The domain name is unusually long."
            )

        if domain.count("-") >= 3:
            findings.append(
                "The domain contains multiple hyphens."
            )

        if domain.count(".") >= 3:
            findings.append(
                "The domain contains multiple subdomains."
            )

    return findings