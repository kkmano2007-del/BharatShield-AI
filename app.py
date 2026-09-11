import os
import requests
import streamlit as st

# ============================================================
# IMPORT SPECIALIZED AGENTS
# ============================================================

from agents.risk_agent import analyze_message
from agents.social_agent import social_engineering_analysis
from agents.financial_agent import financial_risk_analysis
from agents.link_agent import link_analysis
from agents.identity_agent import identity_analysis
from agents.pattern_agent import scam_pattern_analysis

# ============================================================
# IMPORT RAG RETRIEVER
# ============================================================

from rag.retriever import ScamRetriever


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="BharatShield AI",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# LOAD RAG MODEL ONLY ONCE
# ============================================================

@st.cache_resource
def load_retriever():
    return ScamRetriever()


# ============================================================
# OPENROUTER API KEY
# ============================================================

def get_api_key():

    try:
        return st.secrets.get("OPENROUTER_API_KEY")
    except Exception:
        return os.getenv("OPENROUTER_API_KEY")


# ============================================================
# AI REASONING
# ============================================================

def get_ai_reasoning(
    message,
    risk_score,
    retrieved_examples,
    api_key
):

    if not api_key:
        return None

    evidence_text = ""

    for item in retrieved_examples:

        evidence_text += f"""
Category: {item.get("category", "Unknown")}
Known Example: {item.get("message", "")}
Similarity: {item.get("similarity", 0)}
Expected Risk: {item.get("risk", "Unknown")}

"""

    prompt = f"""
You are BharatShield AI, a digital safety investigation assistant.

Analyze the user's message using the evidence retrieved from a scam
knowledge base.

USER MESSAGE:
{message}

CURRENT RULE-BASED RISK SCORE:
{risk_score}/100

RETRIEVED RAG EVIDENCE:
{evidence_text}

Give a concise investigation explanation.

Explain:
1. Whether the message appears suspicious.
2. Which scam techniques or patterns are present.
3. How the message compares with retrieved examples.
4. What the user should do safely.

Do not claim that something is definitely a scam unless the evidence
supports that conclusion. Use cautious language.
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://bharatshield-ai.streamlit.app",
        "X-Title": "BharatShield AI"
    }

    data = {
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.3
    }

    try:

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )

        if response.status_code != 200:
            return None

        result = response.json()

        return result["choices"][0]["message"]["content"]

    except Exception:
        return None


# ============================================================
# CALCULATE RISK SCORE
# ============================================================

def calculate_risk_score(
    risk_results,
    social_results,
    financial_results,
    link_results,
    identity_results,
    pattern_results,
    retrieved_examples
):

    score = 0

    # --------------------------------------------------------
    # SPECIALIZED AGENT SCORES
    # --------------------------------------------------------

    score += min(len(risk_results) * 4, 20)

    score += min(len(social_results) * 6, 18)

    score += min(len(financial_results) * 8, 24)

    score += min(len(link_results) * 5, 15)

    score += min(len(pattern_results) * 8, 25)

    # --------------------------------------------------------
    # RAG SIMILARITY SCORE
    # --------------------------------------------------------

    if retrieved_examples:

        top_example = retrieved_examples[0]

        similarity = float(
            top_example.get("similarity", 0)
        )

        retrieved_risk = (
            top_example.get("risk", "")
            .upper()
        )

        # Strong semantic similarity to known scam

        if (
            similarity >= 0.80
            and retrieved_risk == "HIGH"
        ):
            score += 25

        elif (
            similarity >= 0.65
            and retrieved_risk == "HIGH"
        ):
            score += 18

        elif similarity >= 0.50:
            score += 10

        # Similarity to known safe message

        if (
            similarity >= 0.80
            and retrieved_risk == "LOW"
        ):
            score -= 15

    # --------------------------------------------------------
    # KEEP SCORE BETWEEN 0 AND 100
    # --------------------------------------------------------

    score = max(0, min(score, 100))

    return score


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 70:
        return "HIGH RISK", "🔴"

    elif score >= 40:
        return "MEDIUM RISK", "🟡"

    elif score >= 15:
        return "LOW RISK", "🟢"

    else:
        return "MINIMAL RISK", "🟢"


# ============================================================
# SAFETY RECOMMENDATIONS
# ============================================================

def get_safe_steps(score):

    if score >= 70:

        return [
            "Do not share OTPs, passwords, PINs, or login credentials.",
            "Do not click suspicious links.",
            "Do not send money or make payments because of pressure.",
            "Verify the sender independently using an official website or app.",
            "Contact the relevant organization through official channels."
        ]

    elif score >= 40:

        return [
            "Verify the message independently before taking action.",
            "Avoid clicking links until the sender is confirmed.",
            "Do not share sensitive information.",
            "Use official websites or apps to verify account notifications."
        ]

    else:

        return [
            "No strong scam indicators were detected.",
            "Continue using normal digital safety precautions.",
            "Verify unexpected requests independently."
        ]


# ============================================================
# UI HEADER
# ============================================================

st.title("🛡️ BharatShield AI")

st.subheader(
    "Your Digital Safety Investigation Assistant"
)

st.write(
    """
Paste a suspicious message or link below. BharatShield combines
specialized investigation agents with RAG-based comparison against
known scam patterns.
"""
)

st.divider()


# ============================================================
# USER INPUT
# ============================================================

message = st.text_area(
    "What would you like BharatShield to investigate?",
    placeholder="Paste a suspicious message or link here...",
    height=180
)


# ============================================================
# INVESTIGATE BUTTON
# ============================================================

if st.button(
    "🛡️ Investigate",
    use_container_width=True
):

    if not message.strip():

        st.warning(
            "Please enter a message or link to investigate."
        )

    else:

        with st.spinner(
            "BharatShield agents and RAG system are investigating..."
        ):

            # =================================================
            # AGENT 1 - GENERAL RISK
            # =================================================

            risk_results = analyze_message(
                message
            )


            # =================================================
            # AGENT 2 - SOCIAL ENGINEERING
            # =================================================

            social_results = social_engineering_analysis(
                message
            )


            # =================================================
            # AGENT 3 - FINANCIAL RISK
            # =================================================

            financial_results = financial_risk_analysis(
                message
            )


            # =================================================
            # AGENT 4 - LINK ANALYSIS
            # =================================================

            link_results = link_analysis(
                message
            )


            # =================================================
            # AGENT 5 - IDENTITY ANALYSIS
            # =================================================

            identity_results = identity_analysis(
                message
            )


            # =================================================
            # AGENT 6 - SCAM PATTERN ANALYSIS
            # =================================================

            pattern_results = scam_pattern_analysis(
                social_results,
                financial_results,
                link_results,
                identity_results,
                message
            )


            # =================================================
            # RAG RETRIEVAL
            # =================================================

            retriever = load_retriever()

            retrieved_examples = retriever.retrieve(
                message,
                top_k=3
            )


            # =================================================
            # CALCULATE FINAL RISK SCORE
            # =================================================

            risk_score = calculate_risk_score(
                risk_results,
                social_results,
                financial_results,
                link_results,
                identity_results,
                pattern_results,
                retrieved_examples
            )


            risk_level, emoji = get_risk_level(
                risk_score
            )


            # =================================================
            # OPTIONAL AI REASONING
            # =================================================

            api_key = get_api_key()

            ai_reasoning = get_ai_reasoning(
                message,
                risk_score,
                retrieved_examples,
                api_key
            )


        # =====================================================
        # RESULTS HEADER
        # =====================================================

        st.divider()

        st.header(
            "📊 BharatShield Investigation Result"
        )


        # =====================================================
        # SCORE
        # =====================================================

        col1, col2 = st.columns(2)

        with col1:

            st.metric(
                "Risk Score",
                f"{risk_score}/100"
            )

        with col2:

            st.subheader(
                f"{emoji} {risk_level}"
            )


        st.progress(
            risk_score / 100
        )


        # =====================================================
        # RAG EVIDENCE
        # =====================================================

        st.divider()

        st.header(
            "🧠 RAG Scam Pattern Comparison"
        )

        st.write(
            """
BharatShield searched its knowledge base for messages that are
semantically similar to the submitted message.
"""
        )

        for index, item in enumerate(
            retrieved_examples,
            start=1
        ):

            category = item.get(
                "category",
                "Unknown"
            )

            example_message = item.get(
                "message",
                ""
            )

            similarity = item.get(
                "similarity",
                0
            )

            known_risk = item.get(
                "risk",
                "Unknown"
            )

            with st.expander(
                f"Evidence Match {index} — "
                f"{category} "
                f"({similarity:.0%} similarity)"
            ):

                st.write(
                    "**Known example:**"
                )

                st.write(
                    example_message
                )

                st.write(
                    f"**Knowledge-base risk level:** "
                    f"{known_risk}"
                )

                st.write(
                    f"**Semantic similarity:** "
                    f"{similarity:.1%}"
                )


        # =====================================================
        # AGENT FINDINGS
        # =====================================================

        st.divider()

        st.header(
            "🔍 Specialized Agent Findings"
        )


        agent_data = {

            "🛡️ Risk Agent":
                risk_results,

            "🧠 Social Engineering Agent":
                social_results,

            "💰 Financial Risk Agent":
                financial_results,

            "🔗 Link Analysis Agent":
                link_results,

            "🏢 Identity Analysis Agent":
                identity_results,

            "🔍 Scam Pattern Agent":
                pattern_results
        }


        findings_detected = False


        for agent_name, results in agent_data.items():

            if results:

                findings_detected = True

                with st.expander(
                    agent_name,
                    expanded=True
                ):

                    for finding in results:

                        st.write(
                            f"• {finding}"
                        )


        if not findings_detected:

            st.success(
                "No strong risk indicators were detected by the specialized agents."
            )


        # =====================================================
        # AI REASONING
        # =====================================================

        st.divider()

        st.header(
            "🤖 AI Investigation Reasoning"
        )


        if ai_reasoning:

            st.write(
                ai_reasoning
            )

        else:

            st.info(
                """
AI reasoning is currently unavailable. The rule-based agents and
RAG comparison still completed the investigation successfully.
"""
            )


        # =====================================================
        # SAFE NEXT STEPS
        # =====================================================

        st.divider()

        st.header(
            "🛡️ Safe Next Steps"
        )


        safe_steps = get_safe_steps(
            risk_score
        )


        for step in safe_steps:

            st.write(
                f"• {step}"
            )


        # =====================================================
        # DISCLAIMER
        # =====================================================

        st.divider()

        st.caption(
            """
BharatShield provides an automated risk assessment based on detected
indicators, specialized agents, and similarity to examples in its
knowledge base. It is an investigation aid and does not guarantee that
a message is legitimate or fraudulent.
"""
        )
