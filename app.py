import os
import sys

# Inserts the absolute root directory path into Python's search path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import imaplib
import email
from email.header import decode_header
# Change this line:
from modules.email_analyzer import analyze_email
from modules.threat_detector import detect_threat
from modules.url_analyzer import analyze_urls
from modules.geolocation import analyze_ips
from modules.threat_intel import analyze_indicators
from modules.forensic import build_forensic_timeline
from modules.report import generate_report


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="AI Email Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# SIDEBAR
# ==========================================

st.sidebar.title("🛡️ AI Email Threat Platform")

st.sidebar.write(
    "AI-Powered Email Threat Detection, "
    "GeoLocation and Forensic Intelligence Platform"
)

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "📧 Email Analysis",
        "🔗 URL Analysis",
        "🌍 GeoLocation",
        "🔎 Threat Intelligence",
        "🕵️ Forensic Analysis",
        "📄 Investigation Report"
    ]
)


# ==========================================
# DASHBOARD
# ==========================================

if page == "🏠 Dashboard":

    st.title("🛡️ AI Email Threat Intelligence Platform")

    st.write(
        "AI-Powered Email Threat Detection, "
        "GeoLocation and Forensic Intelligence Platform"
    )

    st.markdown("---")

    # Dashboard metrics

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "📧 Email Analysis",
            "Ready"
        )

    with col2:
        st.metric(
            "🔗 URL Analysis",
            "Ready"
        )

    with col3:
        st.metric(
            "🌍 GeoLocation",
            "Ready"
        )

    with col4:
        st.metric(
            "🕵️ Forensics",
            "Ready"
        )

    st.markdown("---")

    st.subheader("🔍 Platform Capabilities")

    col1, col2 = st.columns(2)

    with col1:

        st.info(
            """
            📧 **Email Threat Detection**

            Analyze email headers, sender information,
            authentication results, suspicious keywords
            and embedded URLs.
            """
        )

        st.info(
            """
            🔗 **URL Security Analysis**

            Detect suspicious URLs, direct IP addresses,
            insecure HTTP connections and suspicious
            URL keywords.
            """
        )

        st.info(
            """
            🌍 **IP GeoLocation**

            Extract IP addresses from email headers and
            identify private, reserved and public IPs.
            """
        )

    with col2:

        st.info(
            """
            🔎 **Threat Intelligence**

            Analyze URLs, domains and IP addresses
            as threat indicators.
            """
        )

        st.info(
            """
            🕵️ **Digital Forensics**

            Build an investigation timeline from
            email evidence.
            """
        )

        st.info(
            """
            📄 **Investigation Report**

            Generate a PDF containing the complete
            investigation results.
            """
        )

    st.markdown("---")

    st.success(
        "✅ Platform is ready for email investigation."
    )


# ==========================================
# EMAIL ANALYSIS
# ==========================================

elif page == "📧 Email Analysis":

    st.title("📧 Email Threat Analysis")

    st.write(
        "Upload an email file (.eml) to perform "
        "AI-powered threat detection and URL analysis."
    )

    uploaded_file = st.file_uploader(
        "📂 Upload Suspicious Email",
        type=["eml"],
        key="email_file_uploader"
    )

    if uploaded_file:

        st.success(
            f"✅ File uploaded: {uploaded_file.name}"
        )

        if st.button(
            "🔍 Analyze Email",
            key="analyze_email_button"
        ):

            with st.spinner(
                "Analyzing email..."
            ):

                # ==================================
                # EMAIL ANALYSIS
                # ==================================

                result = analyze_email(
                    uploaded_file
                )

                # ==================================
                # THREAT DETECTION
                # ==================================

                threat_result = detect_threat(
                    result
                )

                # ==================================
                # URL ANALYSIS
                # ==================================

                url_results = analyze_urls(
                    result["urls"]
                )

                # ==================================
                # IP GEOLOCATION
                # ==================================

                ip_results = analyze_ips(
                    result["headers"]
                )

                # ==================================
                # THREAT INTELLIGENCE
                # ==================================

                indicators = []

                # Add URLs
                indicators.extend(
                    result["urls"]
                )

                # Add IP addresses
                for ip_result in ip_results:

                    indicators.append(
                        ip_result["ip"]
                    )

                # Remove duplicates
                indicators = list(
                    dict.fromkeys(indicators)
                )

                if indicators:

                    ti_results = analyze_indicators(
                        indicators
                    )

                else:

                    ti_results = []

                # ==================================
                # FORENSIC TIMELINE
                # ==================================

                forensic_timeline = (
                    build_forensic_timeline(
                        result,
                        ip_results,
                        threat_result
                    )
                )

            st.success(
                "✅ Email analysis completed!"
            )

            # ==================================
            # AI THREAT DETECTION
            # ==================================

            st.subheader(
                "🤖 AI Threat Detection"
            )

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric(
                    "Risk Score",
                    f"{threat_result['risk_score']}/100"
                )

            with col2:

                st.metric(
                    "Risk Level",
                    threat_result["risk_level"]
                )

            with col3:

                st.metric(
                    "Classification",
                    threat_result["classification"]
                )

            # Threat alert

            if (
                threat_result["classification"]
                == "MALICIOUS"
            ):

                st.error(
                    "🚨 MALICIOUS EMAIL DETECTED"
                )

            elif (
                threat_result["classification"]
                == "SUSPICIOUS"
            ):

                st.warning(
                    "⚠️ SUSPICIOUS EMAIL DETECTED"
                )

            else:

                st.success(
                    "✅ EMAIL APPEARS SAFE"
                )

            # ==================================
            # DETECTION REASONS
            # ==================================

            st.subheader(
                "🔎 Detection Reasons"
            )

            if threat_result["reasons"]:

                for reason in (
                    threat_result["reasons"]
                ):

                    st.warning(
                        f"• {reason}"
                    )

            else:

                st.success(
                    "No major suspicious indicators detected."
                )

            # ==================================
            # EMAIL INFORMATION
            # ==================================

            st.subheader(
                "📋 Email Information"
            )

            col1, col2 = st.columns(2)

            with col1:

                st.write("**👤 Sender**")

                st.code(
                    result["sender"]
                )

                st.write("**👥 Receiver**")

                st.code(
                    result["receiver"]
                )

                st.write("**📝 Subject**")

                st.code(
                    result["subject"]
                )

            with col2:

                st.write("**📅 Date**")

                st.code(
                    result["date"]
                )

                st.write("**↩️ Reply-To**")

                st.code(
                    result["reply_to"]
                )

                st.write("**🆔 Message ID**")

                st.code(
                    result["message_id"]
                )

            # ==================================
            # URL SECURITY ANALYSIS
            # ==================================

            st.subheader(
                "🔗 URL Security Analysis"
            )

            if url_results:

                for index, url_result in enumerate(
                    url_results,
                    start=1
                ):

                    st.write(
                        f"### 🌐 URL {index}"
                    )

                    st.code(
                        url_result["url"]
                    )

                    col1, col2, col3 = (
                        st.columns(3)
                    )

                    with col1:

                        st.write("**Domain**")

                        st.code(
                            url_result["domain"]
                        )

                    with col2:

                        st.metric(
                            "URL Risk",
                            f"{url_result['risk_score']}/100"
                        )

                    with col3:

                        st.write(
                            "**Classification**"
                        )

                        st.write(
                            url_result[
                                "classification"
                            ]
                        )

                    if (
                        url_result[
                            "classification"
                        ]
                        == "HIGH RISK"
                    ):

                        st.error(
                            "🚨 HIGH-RISK URL DETECTED"
                        )

                    elif (
                        url_result[
                            "classification"
                        ]
                        == "SUSPICIOUS"
                    ):

                        st.warning(
                            "⚠️ SUSPICIOUS URL"
                        )

                    else:

                        st.success(
                            "✅ URL APPEARS LOW RISK"
                        )

                    if url_result["reasons"]:

                        st.write(
                            "**🔎 URL Detection Reasons:**"
                        )

                        for reason in (
                            url_result["reasons"]
                        ):

                            st.write(
                                f"• {reason}"
                            )

                    st.markdown("---")

            else:

                st.success(
                    "✅ No URLs detected in this email."
                )

            # ==================================
            # EMAIL BODY
            # ==================================

            st.subheader(
                "📄 Email Body"
            )

            if result["body"]:

                st.text_area(
                    "Extracted Content",
                    result["body"],
                    height=250,
                    key="email_body_display"
                )

            else:

                st.info(
                    "No readable text body found."
                )

            # ==================================
            # IMPORTANT HEADERS
            # ==================================

            st.subheader(
                "🔎 Important Headers"
            )

            for header, values in (
                result["headers"].items()
            ):

                st.write(
                    f"**{header}**"
                )

                for value in values:

                    st.code(
                        value
                    )

            # ==================================
            # IP GEOLOCATION
            # ==================================

            st.subheader(
                "🌍 IP GeoLocation"
            )

            if ip_results:

                for ip_result in ip_results:

                    col1, col2, col3, col4 = (
                        st.columns(4)
                    )

                    with col1:

                        st.write(
                            "**IP Address**"
                        )

                        st.code(
                            ip_result["ip"]
                        )

                    with col2:

                        st.write(
                            "**Status**"
                        )

                        st.write(
                            ip_result["status"]
                        )

                    with col3:

                        st.write(
                            "**Country**"
                        )

                        st.write(
                            ip_result["country"]
                        )

                    with col4:

                        st.write(
                            "**Organization**"
                        )

                        st.write(
                            ip_result["organization"]
                        )

            else:

                st.info(
                    "No IP addresses found in "
                    "the email headers."
                )

            # ==================================
            # THREAT INTELLIGENCE
            # ==================================

            st.subheader(
                "🔎 Threat Intelligence"
            )

            if ti_results:

                for ti_result in ti_results:

                    st.write(
                        f"### 🔍 "
                        f"{ti_result['type']}"
                    )

                    st.code(
                        ti_result["indicator"]
                    )

                    col1, col2, col3 = (
                        st.columns(3)
                    )

                    with col1:

                        st.write("**Risk**")

                        st.write(
                            ti_result["risk"]
                        )

                    with col2:

                        st.metric(
                            "Threat Score",
                            f"{ti_result['score']}/100"
                        )

                    with col3:

                        st.write("**Type**")

                        st.write(
                            ti_result["type"]
                        )

                    st.write(
                        f"**Reason:** "
                        f"{ti_result['reason']}"
                    )

                    st.markdown("---")

            else:

                st.info(
                    "No threat indicators found."
                )

            # ==================================
            # DIGITAL FORENSIC ANALYSIS
            # ==================================

            st.subheader(
                "🕵️ Digital Forensic Analysis"
            )

            st.write(
                "Investigation timeline generated "
                "from email headers, URLs, IP addresses, "
                "authentication results and threat analysis."
            )

            for event in forensic_timeline:

                st.write(
                    f"### 🔹 {event['event']}"
                )

                col1, col2 = st.columns(2)

                with col1:

                    st.write(
                        "**🕒 Timestamp**"
                    )

                    st.code(
                        str(
                            event["timestamp"]
                        )
                    )

                with col2:

                    st.write(
                        "**🔎 Evidence**"
                    )

                    st.code(
                        str(
                            event["evidence"]
                        )
                    )

                st.markdown("---")

            # ==================================
            # INVESTIGATION REPORT
            # ==================================

            st.subheader(
                "📄 Investigation Report"
            )

            report_pdf = generate_report(
                result,
                threat_result,
                url_results,
                ip_results,
                ti_results,
                forensic_timeline
            )

            st.download_button(
                label=(
                    "📥 Download Investigation Report"
                ),
                data=report_pdf,
                file_name=(
                    "email_threat_investigation_report.pdf"
                ),
                mime="application/pdf",
                key="download_report_button"
            )


# ==========================================
# URL ANALYSIS PAGE
# ==========================================

elif page == "🔗 URL Analysis":

    st.title("🔗 URL Security Analysis")

    st.write(
        "Analyze URLs for suspicious security characteristics."
    )

    url_input = st.text_area(
        "Enter URLs (one URL per line)",
        placeholder=(
            "https://example.com\n"
            "https://example.com/login\n"
            "http://192.0.2.10/login"
        )
    )

    if st.button(
        "🔍 Analyze URLs",
        key="standalone_url_button"
    ):

        urls = [
            url.strip()
            for url in url_input.splitlines()
            if url.strip()
        ]

        if urls:

            results = analyze_urls(urls)

            for index, item in enumerate(
                results,
                start=1
            ):

                st.subheader(
                    f"🌐 URL {index}"
                )

                st.code(
                    item["url"]
                )

                col1, col2, col3 = (
                    st.columns(3)
                )

                with col1:

                    st.write("**Domain**")

                    st.code(
                        item["domain"]
                    )

                with col2:

                    st.metric(
                        "Risk Score",
                        f"{item['risk_score']}/100"
                    )

                with col3:

                    st.write(
                        "**Classification**"
                    )

                    st.write(
                        item["classification"]
                    )

                if item["classification"] == "HIGH RISK":

                    st.error(
                        "🚨 HIGH-RISK URL"
                    )

                elif item["classification"] == "SUSPICIOUS":

                    st.warning(
                        "⚠️ SUSPICIOUS URL"
                    )

                else:

                    st.success(
                        "✅ LOW-RISK URL"
                    )

                if item["reasons"]:

                    st.write(
                        "**🔎 Reasons:**"
                    )

                    for reason in item["reasons"]:

                        st.write(
                            f"• {reason}"
                        )

                st.markdown("---")

        else:

            st.warning(
                "Please enter at least one URL."
            )


# ==========================================
# GEOLOCATION PAGE
# ==========================================

elif page == "🌍 GeoLocation":

    st.title(
        "🌍 IP GeoLocation Analysis"
    )

    st.write(
        "Analyze IP addresses extracted from email headers."
    )

    ip_input = st.text_area(
        "Enter IP addresses (one per line)",
        placeholder=(
            "192.0.2.10\n"
            "8.8.8.8"
        )
    )

    if st.button(
        "🌍 Analyze IP Addresses",
        key="standalone_ip_button"
    ):

        import ipaddress

        ips = [
            ip.strip()
            for ip in ip_input.splitlines()
            if ip.strip()
        ]

        if ips:

            for ip in ips:

                try:

                    ip_obj = ipaddress.ip_address(
                        ip
                    )

                    if ip_obj.is_private:

                        status = "PRIVATE"
                        country = "Local Network"
                        organization = "Private Network"

                    elif ip_obj.is_loopback:

                        status = "LOOPBACK"
                        country = "Localhost"
                        organization = "Local Machine"

                    elif ip_obj.is_reserved:

                        status = "RESERVED / TEST"
                        country = "Not Available"
                        organization = (
                            "Documentation/Test Network"
                        )

                    else:

                        status = "PUBLIC"
                        country = "Lookup Required"
                        organization = (
                            "Lookup Required"
                        )

                    col1, col2, col3, col4 = (
                        st.columns(4)
                    )

                    with col1:

                        st.write(
                            "**IP Address**"
                        )

                        st.code(ip)

                    with col2:

                        st.write("**Status**")

                        st.write(status)

                    with col3:

                        st.write("**Country**")

                        st.write(country)

                    with col4:

                        st.write(
                            "**Organization**"
                        )

                        st.write(
                            organization
                        )

                    st.markdown("---")

                except ValueError:

                    st.error(
                        f"❌ Invalid IP address: {ip}"
                    )

        else:

            st.warning(
                "Please enter an IP address."
            )


# ==========================================
# THREAT INTELLIGENCE PAGE
# ==========================================

elif page == "🔎 Threat Intelligence":

    st.title(
        "🔎 Threat Intelligence"
    )

    st.write(
        "Analyze an IP address, URL or domain as a threat indicator."
    )

    indicator_input = st.text_area(
        "Enter indicators (one per line)",
        placeholder=(
            "192.0.2.10\n"
            "https://example.com/login\n"
            "example.com"
        )
    )

    if st.button(
        "🔍 Analyze Indicators",
        key="standalone_ti_button"
    ):

        indicators = [
            item.strip()
            for item in indicator_input.splitlines()
            if item.strip()
        ]

        if indicators:

            results = analyze_indicators(
                indicators
            )

            for item in results:

                st.subheader(
                    f"🔍 {item['type']}"
                )

                st.code(
                    item["indicator"]
                )

                col1, col2, col3 = (
                    st.columns(3)
                )

                with col1:

                    st.write("**Risk**")

                    st.write(
                        item["risk"]
                    )

                with col2:

                    st.metric(
                        "Threat Score",
                        f"{item['score']}/100"
                    )

                with col3:

                    st.write("**Type**")

                    st.write(
                        item["type"]
                    )

                st.write(
                    f"**Reason:** "
                    f"{item['reason']}"
                )

                st.markdown("---")

        else:

            st.warning(
                "Please enter at least one indicator."
            )


# ==========================================
# FORENSIC ANALYSIS PAGE
# ==========================================

elif page == "🕵️ Forensic Analysis":

    st.title(
        "🕵️ Digital Forensic Analysis"
    )

    st.write(
        "Forensic analysis is generated automatically "
        "after an email is analyzed."
    )

    st.info(
        "📧 Go to Email Analysis and upload an .eml "
        "file to generate the forensic investigation timeline."
    )


# ==========================================
# INVESTIGATION REPORT PAGE
# ==========================================

elif page == "📄 Investigation Report":

    st.title(
        "📄 Investigation Report"
    )

    st.write(
        "Investigation reports are generated from "
        "the results of an email analysis."
    )

    st.info(
        "📧 Go to Email Analysis → Upload an .eml file "
        "→ Analyze Email → Download Investigation Report."
    )

# --- AUTOMATED GMAIL INBOX MONITORING ---
@st.fragment(run_every="30s") 
def monitor_gmail_inbox():
    """Background loop that polls Gmail for unread alerts every 30 seconds"""
    
    # 1. Pull credentials securely from the dashboard secrets you just saved
    try:
        GMAIL_USER = st.secrets["GMAIL_USER"]
        GMAIL_APP_PASSWORD = st.secrets["GMAIL_APP_PASSWORD"]
    except KeyError:
        st.warning("🔒 Gmail monitoring is active but missing credentials in Streamlit Secrets.")
        return

    try:
        # 2. Establish connection to Gmail IMAP
        mail = imaplib.IMAP4_SSL("gmail.com")
        mail.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        mail.select("inbox")

        # 3. Check for UNREAD messages
        status, messages = mail.search(None, "UNREAD")
        email_ids = messages.split()

        if email_ids:
            st.toast(f"📬 Found {len(email_ids)} new unread email(s). Processing...")
            
            # 4. Iterate through unread emails
            for e_id in email_ids:
                res, msg_data = mail.fetch(e_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part)
                        
                        # Extract the email Subject line
                        subject, encoding = decode_header(msg["Subject"])[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding or "utf-8", errors="ignore")
                        
                        # Extract the email Body text
                        email_body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    email_body = part.get_payload(decode=True).decode(errors="ignore")
                                    break
                        else:
                            email_body = msg.get_payload(decode=True).decode(errors="ignore")

                        # 5. Send it to your existing core detection tool
                        # (Ensure 'detect_threat' is what your file uses!)
                        analysis_result = detect_threat(email_body)

                        # 6. Active Real-time Alert Popups
                        if "harmful" in analysis_result.lower() or "threat" in analysis_result.lower():
                            st.toast(f"🚨 THREAT DETECTED: '{subject}'", icon="❌")
                            st.error(f"⚠️ **Malicious Email Intercepted!**\n\n**Subject:** {subject}\n\n**AI Forensic Verdict:** {analysis_result}")
                        else:
                            st.toast(f"✅ Safe Email Checked: '{subject}'", icon="🛡️")
                            
                # Mark as read so it isn't processed again on the next 30s rerun
                mail.store(e_id, "+FLAGS", "\\Seen")

        mail.close()
        mail.logout()

    except Exception as e:
        # Silently log errors in small caption text to avoid breaking the interface layout
        st.caption(f"Scanner idle or connecting... Status: {str(e)}")

# --- START RUNNING THE SCANNER ---
st.divider()
st.subheader("📬 Automated Live Inbox Watchdog")
st.write("Status: **Active** (Silently polling your inbox every 30 seconds for incoming alerts)")

# Start the continuous interval fragment loop
monitor_gmail_inbox()

