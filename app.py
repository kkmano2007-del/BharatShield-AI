import streamlit as st
import re
import os
import json
import requests
from urllib.parse import urlparse


# ===================================
# IMPORT MODULAR AGENTS
# ===================================

from agents.risk_agent import analyze_message
from agents.social_agent import social_engineering_analysis
from agents.financial_agent import financial_risk_analysis
from agents.link_agent import link_analysis
from agents.identity_agent import identity_analysis
from agents.pattern_agent import scam_pattern_analysis


# ===================================
# PAGE CONFIGURATION
# ===================================

st.set_page_config(
    page_title="BharatShield AI",
    page_icon="🛡️",
    layout="centered"
)


# ===================================
# AGENT ORCHESTRATOR
# ===================================

def plan_investigation(message):

    text = message.lower()

    plan = []

    if "http://" in text or "https://" in text:
        plan.append("🌐 Link Analysis Agent")

    financial_words = [
        "bank",
        "payment",
        "pay",
        "upi",
        "transfer",
        "money",
        "account",
        "otp",
        "pin",
        "password",
        "login",
        "cvv",
        "reward",
        "prize"
    ]

    if any(word in text for word in financial_words):
        plan.append("💳 Financial Risk Agent")

    social_words = [
        "urgent",
        "immediately",
        "immediate",
        "now",
        "blocked",
        "suspended",
        "within",
        "verify",
        "click"
    ]

    if any(word in text for word in social_words):
        plan.append("🧠 Social Engineering Agent")

    identity_words = [
        "sbi",
        "hdfc",
        "icici",
        "government",
        "police",
        "amazon",
        "flipkart",
        "google",
        "instagram",
        "whatsapp",
        "microsoft"
    ]

    if any(word in text for word in identity_words):
        plan.append("🎭 Identity / Impersonation Agent")

    plan.append("🧩 Scam Pattern Agent")
    plan.append("🤖 AI Investigation Agent")

    return plan


# ===================================
# DOMAIN VS IDENTITY ANALYSIS
# ===================================

def domain_identity_analysis(message, identity_results):

    findings = []

    urls = re.findall(
        r'https?://[^\s]+',
        message
    )

    if not urls or not identity_results:
        return findings

    identity_keywords = {
        "State Bank of India (SBI)": "sbi",
        "HDFC Bank": "hdfc",
        "ICICI Bank": "icici",
        "Amazon": "amazon",
        "Flipkart": "flipkart",
        "Google": "google",
        "Instagram": "instagram",
        "WhatsApp": "whatsapp",
        "Microsoft": "microsoft"
    }

    for url in urls:

        domain = urlparse(url).netloc.lower()

        for identity in identity_results:

            if identity not in identity_keywords:
                continue

            identity_keyword = identity_keywords[identity]

            if identity_keyword not in domain:

                findings.append(
                    f"The message references '{identity}', but the "
                    f"submitted domain '{domain}' does not obviously "
                    f"match that claimed identity."
                )

            else:

                findings.append(
                    f"The submitted domain contains a keyword related "
                    f"to '{identity}', but this alone does not verify "
                    f"authenticity."
                )

    return findings


# ===================================
# IMPROVED RISK SCORING ENGINE
# ===================================

def calculate_risk_score(
    message,
    risk_signals,
    social_results,
    financial_results,
    link_results,
    identity_results,
    domain_results,
    pattern_results
):

    text = message.lower()

    score = 0

    # -----------------------------------
    # 1. BASIC AGENT FINDINGS
    # -----------------------------------

    score += min(
        len(risk_signals) * 4,
        15
    )

    score += min(
        len(social_results) * 6,
        15
    )

    score += min(
        len(financial_results) * 7,
        15
    )

    score += min(
        len(link_results) * 4,
        10
    )

    score += min(
        len(domain_results) * 8,
        15
    )

    score += min(
        len(pattern_results) * 5,
        10
    )

    if identity_results:
        score += 5


    # -----------------------------------
    # 2. HIGH-SEVERITY SENSITIVE DATA
    # -----------------------------------

    sensitive_keywords = [
        "otp",
        "pin",
        "password",
        "cvv",
        "login details",
        "login credentials"
    ]

    sensitive_found = any(
        keyword in text
        for keyword in sensitive_keywords
    )

    if sensitive_found:
        score += 20


    # -----------------------------------
    # 3. LOGIN / ACCOUNT CREDENTIALS
    # -----------------------------------

    credential_keywords = [
        "login",
        "username",
        "account details",
        "credentials"
    ]

    if any(
        keyword in text
        for keyword in credential_keywords
    ):
        score += 10


    # -----------------------------------
    # 4. URGENCY
    # -----------------------------------

    urgency_keywords = [
        "urgent",
        "immediately",
        "immediate",
        "now",
        "today",
        "last chance"
    ]

    urgency_found = any(
        keyword in text
        for keyword in urgency_keywords
    )

    if urgency_found:
        score += 8


    # -----------------------------------
    # 5. THREAT / FEAR
    # -----------------------------------

    threat_keywords = [
        "suspended",
        "blocked",
        "restricted",
        "deactivated",
        "penalty",
        "failure"
    ]

    threat_found = any(
        keyword in text
        for keyword in threat_keywords
    )

    if threat_found:
        score += 10


    # -----------------------------------
    # 6. STRONG COMBINATIONS
    # -----------------------------------

    # OTP/password + urgency

    if sensitive_found and urgency_found:
        score += 10


    # Sensitive information + threat

    if sensitive_found and threat_found:
        score += 10


    # Urgency + threat

    if urgency_found and threat_found:
        score += 8


    # Claimed identity + sensitive request

    if identity_results and sensitive_found:
        score += 8


    # Link + sensitive information

    if link_results and sensitive_found:
        score += 8


    # -----------------------------------
    # LIMIT SCORE
    # -----------------------------------

    score = min(score, 100)


    # -----------------------------------
    # RISK LEVEL
    # -----------------------------------

    if score >= 70:
        level = "HIGH RISK"

    elif score >= 40:
        level = "MEDIUM RISK"

    else:
        level = "LOW RISK"

    return score, level


# ===================================
# EVIDENCE AND UNCERTAINTY ENGINE
# ===================================

def evaluate_evidence(
    risk_signals,
    social_results,
    financial_results,
    link_results,
    identity_results,
    domain_results,
    pattern_results
):

    observed = []
    concerns = []
    unknowns = []

    if risk_signals:
        observed.append(
            "Risk-related indicators were found in the submitted content."
        )

    if link_results:
        observed.append(
            "A web link was detected and its visible domain was extracted."
        )

    if identity_results:
        observed.append(
            "The content references one or more recognizable organizations or platforms."
        )

    if social_results:
        concerns.append(
            "Possible pressure or social-engineering techniques were detected."
        )

    if financial_results:
        concerns.append(
            "Possible financial or sensitive-information risk was detected."
        )

    if domain_results:
        concerns.append(
            "The claimed identity and submitted domain require independent verification."
        )

    if pattern_results:
        concerns.append(
            "Multiple indicators form a potentially concerning interaction pattern."
        )

    unknowns.append(
        "The sender's true identity cannot be confirmed from the submitted text alone."
    )

    unknowns.append(
        "A suspicious-looking domain does not by itself prove fraud."
    )

    unknowns.append(
        "No automated assessment should be treated as proof that something is definitely fraudulent or definitely safe."
    )

    if (
        domain_results
        and social_results
        and financial_results
        and pattern_results
    ):

        assessment = "HIGH CAUTION"

        explanation = (
            "Multiple independent categories of concerning indicators are present."
        )

    elif len(concerns) >= 2:

        assessment = "NEEDS VERIFICATION"

        explanation = (
            "Multiple potential concerns were detected, but the available evidence does not independently confirm fraud."
        )

    else:

        assessment = "INSUFFICIENT EVIDENCE"

        explanation = (
            "The submitted content does not provide enough reliable evidence for a strong conclusion."
        )

    return (
        observed,
        concerns,
        unknowns,
        assessment,
        explanation
    )


# ===================================
# AI INVESTIGATION AGENT
# ===================================

def ai_investigation(message):

    api_key = os.getenv(
        "OPENROUTER_API_KEY"
    )

    if not api_key:

        return {
            "error": (
                "OpenRouter API key was not found. "
                "Please set OPENROUTER_API_KEY and run Streamlit "
                "from the same PowerShell terminal."
            )
        }

    url = (
        "https://openrouter.ai/api/v1/chat/completions"
    )

    prompt = f"""
You are BharatShield AI, a digital safety investigation assistant.

Analyze the suspicious message below carefully.

IMPORTANT RULES:

1. Do not claim something is definitely a scam unless there is strong evidence.
2. Separate observations from suspicions.
3. Clearly state uncertainty.
4. Identify possible impersonation claims.
5. Identify what action the sender wants the recipient to take.
6. Identify possible social-engineering techniques.
7. Identify possible financial or sensitive-information risks.
8. Provide safe next steps.
9. Do not ask the user to click suspicious links.
10. Do not invent facts about the sender or website.
11. Return ONLY valid JSON.

Return exactly this JSON structure:

{{
    "summary": "",
    "claimed_identity": "",
    "requested_action": "",
    "social_engineering": [],
    "financial_or_sensitive_risks": [],
    "suspicious_indicators": [],
    "uncertainties": [],
    "recommended_actions": [],
    "risk_assessment": "LOW / NEEDS VERIFICATION / HIGH CAUTION"
}}

Suspicious message:

{message}
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    data = {
        "model": "openrouter/free",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.2
    }

    try:

        response = requests.post(
            url,
            headers=headers,
            json=data,
            timeout=90
        )

        if response.status_code != 200:

            return {
                "error": (
                    f"AI request failed with status code "
                    f"{response.status_code}."
                )
            }

        response_data = response.json()

        ai_text = (
            response_data["choices"][0]["message"]["content"]
        )

        ai_text = ai_text.strip()

        # Remove markdown code blocks if returned

        if ai_text.startswith("```"):

            ai_text = re.sub(
                r"^```(?:json)?\s*",
                "",
                ai_text
            )

            ai_text = re.sub(
                r"\s*```$",
                "",
                ai_text
            )

            ai_text = ai_text.strip()

        return json.loads(ai_text)

    except json.JSONDecodeError:

        return {
            "error": (
                "The AI returned an unexpected response format. "
                "Please try again."
            )
        }

    except requests.exceptions.Timeout:

        return {
            "error": (
                "The AI request timed out. Please try again."
            )
        }

    except Exception as error:

        return {
            "error": str(error)
        }


# ===================================
# MAIN USER INTERFACE
# ===================================

st.title("🛡️ BharatShield AI")

st.subheader(
    "Your Digital Safety Investigation Assistant"
)

st.write(
    "Paste a suspicious message or link. BharatShield coordinates "
    "multiple specialized agents to investigate potential digital "
    "safety risks."
)


user_input = st.text_area(
    "What would you like BharatShield to investigate?",
    placeholder="Paste a suspicious message or link here...",
    height=180
)


# ===================================
# INVESTIGATION BUTTON
# ===================================

if st.button("🛡️ Investigate"):

    if not user_input.strip():

        st.warning(
            "Please enter a message or link first."
        )

    else:

        with st.spinner(
            "BharatShield agents are investigating..."
        ):

            # AGENT 1
            risk_signals = analyze_message(
                user_input
            )

            # ORCHESTRATOR
            plan = plan_investigation(
                user_input
            )

            # AGENT 2
            social_results = social_engineering_analysis(
                user_input
            )

            # AGENT 3
            financial_results = financial_risk_analysis(
                user_input
            )

            # AGENT 4
            link_results = link_analysis(
                user_input
            )

            # AGENT 5
            identity_results = identity_analysis(
                user_input
            )

            # DOMAIN ANALYSIS
            domain_results = domain_identity_analysis(
                user_input,
                identity_results
            )

            # AGENT 6
            pattern_results = scam_pattern_analysis(
                social_results,
                financial_results,
                link_results,
                identity_results,
                user_input
            )

            # RISK SCORE
            risk_score, risk_level = calculate_risk_score(
                user_input,
                risk_signals,
                social_results,
                financial_results,
                link_results,
                identity_results,
                domain_results,
                pattern_results
            )

            # EVIDENCE ENGINE
            (
                observed,
                concerns,
                unknowns,
                assessment,
                explanation
            ) = evaluate_evidence(
                risk_signals,
                social_results,
                financial_results,
                link_results,
                identity_results,
                domain_results,
                pattern_results
            )

            # AI AGENT
            ai_results = ai_investigation(
                user_input
            )


        # ===================================
        # RISK SCORE DASHBOARD
        # ===================================

        st.write(
            "## 📊 BharatShield Risk Score"
        )

        col1, col2 = st.columns(2)

        with col1:

            st.metric(
                "Risk Score",
                f"{risk_score}/100"
            )

        with col2:

            if risk_level == "HIGH RISK":

                st.error(
                    "🔴 HIGH RISK"
                )

            elif risk_level == "MEDIUM RISK":

                st.warning(
                    "🟡 MEDIUM RISK"
                )

            else:

                st.success(
                    "🟢 LOW RISK"
                )

        st.progress(
            risk_score / 100
        )

        st.caption(
            "The score is based on detected indicators and their combinations. "
            "It is an investigation aid and not proof that a message is fraudulent."
        )

        st.divider()


        # ===================================
        # INVESTIGATION PLAN
        # ===================================

        st.write(
            "## 🤖 Investigation Plan"
        )

        for agent in plan:

            st.write(
                "• " + agent
            )

        st.divider()


        # ===================================
        # AGENT RESULTS
        # ===================================

        if risk_signals:

            st.write(
                "## 🚨 Risk Signal Agent"
            )

            for result in risk_signals:

                st.write(
                    "• " + result
                )


        if social_results:

            st.write(
                "## 🧠 Social Engineering Agent"
            )

            for result in social_results:

                st.write(
                    "• " + result
                )


        if financial_results:

            st.write(
                "## 💳 Financial Risk Agent"
            )

            for result in financial_results:

                st.write(
                    "• " + result
                )


        if link_results:

            st.write(
                "## 🌐 Link Analysis Agent"
            )

            for result in link_results:

                st.write(
                    "• " + result
                )


        if identity_results:

            st.write(
                "## 🎭 Identity Agent"
            )

            for identity in identity_results:

                st.write(
                    "• Claimed or referenced identity: "
                    + identity
                )


        if domain_results:

            st.write(
                "## 🔎 Domain vs Identity Evidence"
            )

            for result in domain_results:

                st.write(
                    "• " + result
                )


        if pattern_results:

            st.write(
                "## 🧩 Scam Pattern Agent"
            )

            for result in pattern_results:

                st.write(
                    "• " + result
                )


        # ===================================
        # AI INVESTIGATION
        # ===================================

        st.divider()

        st.write(
            "## 🤖 AI Investigation Agent"
        )


        if "error" in ai_results:

            st.warning(
                ai_results["error"]
            )

        else:

            st.write(
                "### 📝 AI Summary"
            )

            st.write(
                ai_results.get(
                    "summary",
                    "No summary available."
                )
            )


            if ai_results.get(
                "claimed_identity"
            ):

                st.write(
                    "### 🎭 Claimed Identity"
                )

                st.write(
                    ai_results["claimed_identity"]
                )


            if ai_results.get(
                "requested_action"
            ):

                st.write(
                    "### 👉 Requested Action"
                )

                st.write(
                    ai_results["requested_action"]
                )


            if ai_results.get(
                "social_engineering"
            ):

                st.write(
                    "### 🧠 AI Social Engineering Analysis"
                )

                for item in ai_results[
                    "social_engineering"
                ]:

                    st.write(
                        "• " + item
                    )


            if ai_results.get(
                "financial_or_sensitive_risks"
            ):

                st.write(
                    "### 💳 Financial / Sensitive Information Risks"
                )

                for item in ai_results[
                    "financial_or_sensitive_risks"
                ]:

                    st.write(
                        "• " + item
                    )


            if ai_results.get(
                "suspicious_indicators"
            ):

                st.write(
                    "### ⚠️ Suspicious Indicators"
                )

                for item in ai_results[
                    "suspicious_indicators"
                ]:

                    st.write(
                        "• " + item
                    )


            if ai_results.get(
                "uncertainties"
            ):

                st.write(
                    "### ❓ AI Uncertainties"
                )

                for item in ai_results[
                    "uncertainties"
                ]:

                    st.write(
                        "• " + item
                    )


            if ai_results.get(
                "recommended_actions"
            ):

                st.write(
                    "### 🛡️ AI Recommended Actions"
                )

                for item in ai_results[
                    "recommended_actions"
                ]:

                    st.write(
                        "• " + item
                    )


            if ai_results.get(
                "risk_assessment"
            ):

                st.write(
                    "### 🔍 AI Risk Assessment"
                )

                ai_risk = (
                    ai_results[
                        "risk_assessment"
                    ]
                    .upper()
                    .strip()
                )

                if ai_risk == "HIGH CAUTION":

                    st.error(
                        "🟠 HIGH CAUTION"
                    )

                elif ai_risk == "NEEDS VERIFICATION":

                    st.warning(
                        "🟡 NEEDS VERIFICATION"
                    )

                else:

                    st.info(
                        "⚪ " + ai_risk
                    )


        # ===================================
        # EVIDENCE & UNCERTAINTY
        # ===================================

        st.divider()

        st.write(
            "## ⚖️ Evidence & Uncertainty Analysis"
        )


        st.write(
            "### ✅ What We Observed"
        )

        for item in observed:

            st.write(
                "• " + item
            )


        st.write(
            "### ⚠️ Potential Concerns"
        )

        for item in concerns:

            st.write(
                "• " + item
            )


        st.write(
            "### ❓ What We Cannot Yet Verify"
        )

        for item in unknowns:

            st.write(
                "• " + item
            )


        # ===================================
        # OVERALL ASSESSMENT
        # ===================================

        st.divider()

        st.write(
            "## 🔍 Overall Risk Assessment"
        )


        if assessment == "HIGH CAUTION":

            st.error(
                "🟠 HIGH CAUTION — "
                + explanation
            )

        elif assessment == "NEEDS VERIFICATION":

            st.warning(
                "🟡 NEEDS VERIFICATION — "
                + explanation
            )

        else:

            st.info(
                "⚪ INSUFFICIENT EVIDENCE — "
                + explanation
            )


        # ===================================
        # SAFE NEXT STEPS
        # ===================================

        st.divider()

        st.write(
            "## 🛡️ Safe Next Steps"
        )

        st.write(
            "• Do not rush into making payments.\n"
            "• Do not share OTPs, PINs, passwords, or sensitive information.\n"
            "• Do not click suspicious links.\n"
            "• Verify suspicious requests independently using official contact information.\n"
            "• Treat automated analysis as guidance, not proof."
        )