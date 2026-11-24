"""WebGuard - Python-Based Phishing Detection System (Streamlit app).
Run with:  streamlit run app.py
"""
import streamlit as st
import detector
import database

st.set_page_config(page_title="WebGuard", page_icon="🛡️", layout="centered")
database.init_db()

# ---------- Basic CSS styling ----------
st.markdown(
    """
    <style>
    .wg-title {font-size: 2.4rem; font-weight: 800; margin-bottom: 0;}
    .wg-sub {color: #6b7280; margin-top: 0;}
    .wg-card {padding: 1.1rem 1.3rem; border-radius: 12px; margin: 0.8rem 0; color: #fff; font-size: 1.2rem; font-weight: 700;}
    .high {background: #dc2626;} .medium {background: #f59e0b;} .low {background: #16a34a;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<p class="wg-title">🛡️ WebGuard</p>', unsafe_allow_html=True)
st.markdown('<p class="wg-sub">Python-Based Phishing Detection System</p>', unsafe_allow_html=True)

tab_msg, tab_url, tab_hist, tab_about = st.tabs(["📩 Message Checker", "🔗 URL Checker", "🕘 Scan History", "ℹ️ About"])


def show_result(score, reasons, scan_type, content, urls=None):
    category = detector.risk_category(score)
    css = {"HIGH RISK": "high", "MEDIUM RISK": "medium", "LOW RISK": "low"}[category]
    st.markdown(f'<div class="wg-card {css}">{category} &nbsp;|&nbsp; Score: {score}/100</div>', unsafe_allow_html=True)
    st.progress(score / 100)

    st.subheader("Why?")
    if reasons:
        for r in reasons:
            st.write("⚠️ " + r)
    else:
        st.write("✅ No suspicious indicators found.")

    if urls:
        st.subheader("Links found")
        for u in urls:
            st.write(f"**{u['url']}** → {u['score']}/100")
            for r in u["reasons"]:
                st.caption("• " + r)

    st.subheader("Safety advice")
    for tip in detector.safety_advice(category):
        st.write("• " + tip)

    database.save_scan(scan_type, content, score, category)


with tab_msg:
    st.write("Paste a suspicious SMS, email or WhatsApp message.")
    msg = st.text_area("Message", height=180, placeholder="Dear customer, your account will be blocked. Verify now: http://...")
    if st.button("Analyze Message", type="primary"):
        if msg.strip():
            res = detector.analyze_message(msg)
            show_result(res["score"], res["reasons"], "message", msg, res["urls"])
        else:
            st.warning("Please enter a message first.")

with tab_url:
    st.write("Enter a link to check before you open it.")
    url = st.text_input("URL", placeholder="http://paypal.secure-login.xyz/verify")
    if st.button("Analyze URL", type="primary"):
        if url.strip():
            res = detector.analyze_url(url)
            show_result(res["score"], res["reasons"], "url", url)
        else:
            st.warning("Please enter a URL first.")

with tab_hist:
    rows = database.get_history()
    if rows:
        st.dataframe(
            [{"Time": r[0], "Type": r[1], "Content": r[2][:80], "Score": r[3], "Category": r[4]} for r in rows],
            use_container_width=True,
        )
        if st.button("Clear history"):
            database.clear_history()
            st.rerun()
    else:
        st.info("No scans yet.")

with tab_about:
    st.write(
        "WebGuard uses rule-based analysis (keywords, regular expressions and URL features) "
        "to estimate how likely a message or link is to be phishing. "
        "It is a learning project and gives an estimate only, not a guarantee."
    )
    st.write("**Tech:** Python, Streamlit, CSS, SQLite")
