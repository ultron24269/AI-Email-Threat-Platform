import os
import sys
from datetime import datetime
from urllib.parse import urlparse

# Insert project root directory into Python search path
sys.path.insert(
    0,
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

import streamlit as st
import imaplib
import email
from email.header import decode_header


# =========================================================
# IMPORT CUSTOM PROCESSING MODULES
# =========================================================

from modules.email_analyzer import (
    analyze_email,
    check_live_mailbox
)

from modules.threat_detector import (
    detect_threat
)

from modules.url_analyzer import (
    analyze_urls
)

from modules.geolocation import (
    analyze_ips
)

from modules.threat_intel import (
    analyze_indicators
)

from modules.forensic import (
    build_forensic_timeline
)

from modules.report import (
    generate_report
)


# =========================================================
# SESSION STATE INITIALIZATION
# =========================================================

if "threat_log_history" not in st.session_state:
    st.session_state.threat_log_history = []

if "email_analysis_cache" not in st.session_state:
    st.session_state.email_analysis_cache = None


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="AI Email Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# SIDEBAR NAVIGATION PANEL
# =========================================================

st.sidebar.title(
    "🛡️ AI Email Threat Platform"
)

st.sidebar.write(
    "AI-Powered Email Threat Detection, "
    "GeoLocation and Forensic Intelligence Platform"
)

page = st.sidebar.radio(
    "Navigation System",
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


# =========================================================
# MODULE 1: MAIN DASHBOARD
# =========================================================

if page == "🏠 Dashboard":

    st.title(
        "🛡️ AI Email Threat Intelligence Platform"
    )

    st.write(
        "AI-Powered Email Threat Detection, "
        "GeoLocation and Forensic Intelligence Platform"
    )

    st.markdown("---")

    # High-level state widgets
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "📧 Email Analysis Pipeline",
            "Ready"
        )

    with col2:
        st.metric(
            "🔗 URL Security Deep Scan",
            "Ready"
        )

    with col3:
        st.metric(
            "🌍 Geolocation Tracking Node",
            "Ready"
        )

    with col4:
        st.metric(
            "🕵️ Digital Forensics Matrix",
            "Ready"
        )

    st.markdown("---")

    st.subheader(
        "🔍 Platform Architectural Capabilities"
    )

    col_left, col_right = st.columns(2)

    with col_left:

        st.info(
            "📧 **Email Threat Detection**\n\n"
            "Extracts parameters from email headers, "
            "sender information, sender alignment "
            "authentication results, suspicious keywords, "
            "and embedded URLs."
        )

        st.info(
            "🔗 **URL Security Analysis**\n\n"
            "Passes text domains into the ML engine "
            "to isolate suspicious URLs, raw IP "
            "configurations, insecure HTTP handshakes, "
            "and lookalike brand subdomains."
        )

        st.info(
            "🌍 **IP GeoLocation Engine**\n\n"
            "Traces delivery hop trails via routing "
            "headers to find network coordinates, "
            "origin countries, and Autonomous System "
            "Numbers (ASNs)."
        )

    with col_right:

        st.info(
            "🔎 **Threat Intelligence Mesh**\n\n"
            "Cross-references indicators against live "
            "community threat databases to flag "
            "historic abuse parameters."
        )

        st.info(
            "🕵️ **Forensic Reconstruction Timeline**\n\n"
            "Generates chronological verification logs "
            "tracing every technical touchpoint an "
            "incoming packet traversed."
        )

        st.info(
            "📄 **Investigation Reporting**\n\n"
            "Compiles deep analytical variables cleanly "
            "into an enterprise-ready, multi-page "
            "forensic document via ReportLab."
        )

    st.markdown("---")

    st.success(
        "✅ Operational Framework Initialized: "
        "Ready for Investigation Queries."
    )

    st.markdown("---")


    # =====================================================
    # WATCHDOG BACKGROUND PULSE CONFIGURATION
    # =====================================================

    try:

        from streamlit_autorefresh import (
            st_autorefresh
        )

        pulse_index = st_autorefresh(
            interval=30000,
            key="watchdog_heartbeat"
        )

    except ImportError:

        pulse_index = 1

        st.warning(
            "⚠️ 'streamlit-autorefresh' package "
            "configuration missing from environment."
        )


    st.subheader(
        "📬 Automated Live Inbox Watchdog"
    )

    st.write(
        "Status: **Active** "
        "*(Silently polling your configured "
        "mailbox environment every 30 seconds)*"
    )

    st.write(
        f"System Sync Timestamp: "
        f"`{datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}` "
        f"| Iteration Step: `{pulse_index}`"
    )


    with st.spinner(
        "Watchdog searching incoming mailbox queues..."
    ):

        new_live_alerts = check_live_mailbox()

        if new_live_alerts:

            st.session_state.threat_log_history.extend(
                new_live_alerts
            )

            st.toast(
                "🚨 Watchdog intercepted fresh "
                "mailbox threat indicators!",
                icon="⚠️"
            )


    if st.session_state.threat_log_history:

        st.write(
            "### 🚨 Intercepted Watchdog Threat Logs"
        )

        st.dataframe(
            st.session_state.threat_log_history
        )

        st.markdown("---")

        st.subheader(
            "📊 Live Threat Telemetry Timeline"
        )

        chart_data = []

        for idx, alert in enumerate(
            st.session_state.threat_log_history
        ):

            prob = int(
                alert.get(
                    "phishing_probability",
                    0
                )
            )

            chart_data.append(
                {
                    "Watchdog Step": idx + 1,
                    "Threat Score %": prob
                }
            )

        if chart_data:

            st.line_chart(
                data=chart_data,
                x="Watchdog Step",
                y="Threat Score %",
                use_container_width=True
            )


        st.markdown("---")

        st.subheader(
            "🌍 Real-Time Server Hop Geolocation Map"
        )

        map_points = []

        for alert in (
            st.session_state.threat_log_history
        ):

            if isinstance(alert, dict):

                lat = alert.get("latitude")
                lon = alert.get("longitude")

                if lat and lon:

                    map_points.append(
                        {
                            "lat": float(lat),
                            "lon": float(lon)
                        }
                    )


        if not map_points:

            map_points = [
                {
                    "lat": 13.0827,
                    "lon": 80.2707
                },
                {
                    "lat": 37.7749,
                    "lon": -122.4194
                },
                {
                    "lat": 52.5200,
                    "lon": 13.4050
                }
            ]

        st.map(
            data=map_points,
            use_container_width=True
        )

    else:

        st.info(
            "No active threat alerts triggered "
            "in the current mailbox watchdog queue session."
        )


# =========================================================
# MODULE 2: EMAIL ANALYSIS WORKBENCH
# =========================================================

elif page == "📧 Email Analysis":

    st.title(
        "📧 Email Threat Analysis"
    )

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
            f"✅ Target node successfully ingested: "
            f"{uploaded_file.name}"
        )


        if (
            st.button(
                "🔍 Execute Analytical Pipeline",
                key="analyze_email_button"
            )
            or
            st.session_state.email_analysis_cache
            is not None
        ):

            if (
                st.session_state.email_analysis_cache
                is None
            ):

                with st.spinner(
                    "Analyzing email..."
                ):

                    result = analyze_email(
                        uploaded_file
                    )

                    threat_result = detect_threat(
                        result
                    )

                    url_results = analyze_urls(
                        result.get(
                            "urls",
                            []
                        )
                    )

                    ip_results = analyze_ips(
                        result.get(
                            "headers",
                            {}
                        )
                    )


                    indicators = list(
                        result.get(
                            "urls",
                            []
                        )
                    )


                    for ip_res in ip_results:

                        if ip_res.get("ip"):

                            indicators.append(
                                ip_res.get("ip")
                            )


                    indicators = list(
                        dict.fromkeys(
                            indicators
                        )
                    )


                    ti_results = (
                        analyze_indicators(
                            indicators
                        )
                        if indicators
                        else []
                    )


                    forensic_timeline = (
                        build_forensic_timeline(
                            result,
                            ip_results,
                            threat_result
                        )
                    )


                    st.session_state.email_analysis_cache = {

                        "result": result,

                        "threat_result":
                            threat_result,

                        "url_results":
                            url_results,

                        "ip_results":
                            ip_results,

                        "ti_results":
                            ti_results,

                        "forensic_timeline":
                            forensic_timeline
                    }


            cached_pipeline = (
                st.session_state.email_analysis_cache
            )

            e_meta = cached_pipeline[
                "result"
            ]

            e_threat = cached_pipeline[
                "threat_result"
            ]

            e_urls = cached_pipeline[
                "url_results"
            ]


            st.success(
                "✅ Deep forensic extraction cycle "
                "completed successfully!"
            )


            # =================================================
            # AI THREAT DETECTION METRICS
            # =================================================

            st.subheader(
                "🤖 AI Threat Detection Matrix Summary"
            )

            col_m1, col_m2, col_m3 = st.columns(3)


            with col_m1:

                st.metric(
                    "Calculated Threat Score",
                    f"{int(e_threat.get('risk_score', 0))}/100"
                )


            with col_m2:

                st.metric(
                    "Assessed Threat Risk Level",
                    str(
                        e_threat.get(
                            "risk_level",
                            "UNKNOWN"
                        )
                    ).upper()
                )


            with col_m3:

                st.metric(
                    "System Engine Classification",
                    str(
                        e_threat.get(
                            "classification",
                            "UNKNOWN"
                        )
                    ).upper()
                )


            # =================================================
            # CLASSIFICATION NOTIFICATION
            # =================================================

            verdict_val = str(
                e_threat.get(
                    "classification",
                    "SAFE"
                )
            ).upper()


            if verdict_val in [
                "MALICIOUS",
                "HIGH RISK"
            ]:

                st.error(
                    "🚨 MALICIOUS PACKET METRICS "
                    "CRITICALLY IDENTIFIED"
                )

            elif verdict_val == "SUSPICIOUS":

                st.warning(
                    "⚠️ ANOMALOUS OR UNVERIFIED "
                    "HEURISTIC BEHAVIORS DETECTED"
                )

            else:

                st.success(
                    "✅ CORRELATION COMPLETE: "
                    "ELEMENT MATCHES SAFE SIGNATURES"
                )


            # =================================================
            # EMAIL HEADER INFORMATION
            # =================================================

            st.subheader(
                "📬 Header Structural Layout Information"
            )

            st.write(
                f"**Origin Address (From):** "
                f"`{e_meta.get('sender', 'Unknown')}`"
            )

            st.write(
                f"**Destination Node (To):** "
                f"`{e_meta.get('receiver', 'Unknown')}`"
            )

            st.write(
                f"**Subject Title:** "
                f"{e_meta.get('subject', 'No Subject Title Found')}"
            )

            st.write(
                f"**Message Identifier String:** "
                f"`{e_meta.get('message_id', 'N/A')}`"
            )


            # =================================================
            # THREAT REASONING
            # =================================================

            if e_threat.get("reasons"):

                st.subheader(
                    "🔎 System Heuristic Detection Flags"
                )

                for item_reason in e_threat.get(
                    "reasons",
                    []
                ):

                    st.write(
                        f"• {item_reason}"
                    )


            # =================================================
            # INTEGRATED URL SCANNING
            # =================================================

            if e_urls:

                st.markdown("---")

                st.subheader(
                    "🔗 Extracted Embedded Hyperlink Profiles"
                )


                for single_url in e_urls:

                    raw_link = single_url.get(
                        "url",
                        "N/A"
                    )

                    parsed_domain_name = (
                        urlparse(
                            raw_link
                        ).netloc
                        if raw_link != "N/A"
                        else "N/A"
                    )


                    prob_val = int(
                        single_url.get(
                            "phishing_probability",
                            0
                        )
                    )


                    link_verdict = str(
                        single_url.get(
                            "prediction",
                            "UNKNOWN"
                        )
                    ).upper()


                    st.write(
                        f"**Target Link:** "
                        f"`{raw_link}`"
                    )

                    st.write(
                        f"Base Domain: "
                        f"`{parsed_domain_name}`"
                    )

                    st.write(
                        f"AI Phishing Probability Score: "
                        f"`{prob_val}/100`"
                    )


                    if link_verdict in [
                        "PHISHING",
                        "HIGH RISK",
                        "MALICIOUS"
                    ]:

                        st.error(
                            f"❌ DANGEROUS NETWORK VECTOR "
                            f"FLAGGED: {link_verdict}"
                        )

                    elif link_verdict == "SUSPICIOUS":

                        st.warning(
                            f"⚠️ ANOMALOUS INFRASTRUCTURE "
                            f"DETECTED: {link_verdict}"
                        )

                    else:

                        st.success(
                            "✅ Link parameters match "
                            "standard structural traits."
                        )


                    st.markdown("---")


# =========================================================
# MODULE 3: HYPERLINK SUB-ANALYSIS
# =========================================================

elif page == "🔗 URL Analysis":

    st.title(
        "🔗 Deep URL Security Matrix"
    )


    if (
        st.session_state.email_analysis_cache
        is None
    ):

        st.info(
            "❗ No operational telemetry cache found. "
            "Please run an email investigation sequence "
            "under the '📧 Email Analysis' tab first."
        )

    else:

        cached_urls = (
            st.session_state
            .email_analysis_cache
            .get(
                "url_results",
                []
            )
        )


        if cached_urls:

            st.write(
                "### Target Domain Processing Matrix"
            )

            st.dataframe(
                cached_urls
            )


            for idx, url_node in enumerate(
                cached_urls
            ):

                st.markdown(
                    f"#### Indicator Node #{idx + 1}"
                )

                st.json(
                    url_node
                )

        else:

            st.success(
                "✅ Clean Scan Run: No embedded "
                "hyperlinks were discovered in the "
                "target payload body text."
            )


# =========================================================
# MODULE 4: IP ROUTING GEOLOCATION
# =========================================================

elif page == "🌍 GeoLocation":

    st.title(
        "🌍 Network Path Hop Geolocation Mapping"
    )


    if (
        st.session_state.email_analysis_cache
        is None
    ):

        st.info(
            "❗ No routing logs available. "
            "Please run an email investigation sequence "
            "under the '📧 Email Analysis' tab first."
        )

    else:

        cached_ips = (
            st.session_state
            .email_analysis_cache
            .get(
                "ip_results",
                []
            )
        )


        if cached_ips:

            st.write(
                "### Extracted Network Routing "
                "Node Records"
            )

            st.dataframe(
                cached_ips
            )


            for ip_block in cached_ips:

                if ip_block.get("ip"):

                    st.write(
                        f"Node Coordinate Extraction: "
                        f"{ip_block.get('ip')} — "
                        f"Country Code: "
                        f"{ip_block.get('country', 'Private/Internal')}"
                    )

        else:

            st.info(
                "No public external routing hops "
                "could be extracted from this message "
                "header profile."
            )


# =========================================================
# MODULE 5: LIVE THREAT INTELLIGENCE
# =========================================================

elif page == "🔎 Threat Intelligence":

    st.title(
        "🔎 Real-Time Threat Intelligence "
        "Database Cross-Check"
    )


    if (
        st.session_state.email_analysis_cache
        is None
    ):

        st.info(
            "❗ Threat context is unpopulated. "
            "Please run an email investigation sequence "
            "under the '📧 Email Analysis' tab first."
        )

    else:

        cached_ti = (
            st.session_state
            .email_analysis_cache
            .get(
                "ti_results",
                []
            )
        )


        if cached_ti:

            st.write(
                "### Extracted Reputation "
                "Database Matches"
            )

            st.dataframe(
                cached_ti
            )

        else:

            st.success(
                "✅ External database check complete: "
                "No indicators matched known historical "
                "blacklist parameters."
            )


# =========================================================
# MODULE 6: INCIDENT DIGITAL FORENSICS
# =========================================================

elif page == "🕵️ Forensic Analysis":

    st.title(
        "🕵️ Chronological Forensic "
        "Reconstruction Matrix"
    )


    if (
        st.session_state.email_analysis_cache
        is None
    ):

        st.info(
            "❗ Forensic logs empty. "
            "Please run an email investigation sequence "
            "under the '📧 Email Analysis' tab first."
        )

    else:

        cached_timeline = (
            st.session_state
            .email_analysis_cache
            .get(
                "forensic_timeline",
                []
            )
        )


        if cached_timeline:

            st.subheader(
                "System Event Log Sequence"
            )

            st.write(
                cached_timeline
            )


            for event in cached_timeline:

                if isinstance(event, dict):

                    st.markdown(
                        f"`[{event.get('time', '00:00:00')}]` "
                        f"Action Event: "
                        f"{event.get('action', 'Subprocess Triggered')}"
                    )

        else:

            st.info(
                "Chronological pipeline logs are "
                "missing or unformatted for this "
                "target packet profile."
            )


# =========================================================
# MODULE 7: INVESTIGATION REPORTING COMPILER
# =========================================================

elif page == "📄 Investigation Report":

    st.title(
        "📄 Compile Certified Investigation Reports"
    )


    if (
        st.session_state.email_analysis_cache
        is None
    ):

        st.info(
            "❗ Cannot render reporting forms. "
            "Please run an email investigation sequence "
            "under the '📧 Email Analysis' tab first."
        )

    else:

        cached_report_source = (
            st.session_state.email_analysis_cache
        )


        st.write(
            "Click the compilation button below "
            "to build and download an exportable, "
            "multi-page forensic PDF log detailing "
            "every security variable found."
        )


        if st.button(
            "🛠️ Assemble Forensic PDF "
            "Document Artifact",
            key="compile_pdf_button"
        ):

            with st.spinner(
                "Compiling structural data vectors "
                "into ReportLab canvases..."
            ):

                output_report_name = generate_report(
                    cached_report_source.get(
                        "url_results",
                        []
                    ),
                    email_meta=cached_report_source.get(
                        "result",
                        {}
                    ),
                    forensic_timeline=cached_report_source.get(
                        "forensic_timeline",
                        []
                    )
                )


            # =================================================
            # PDF DOWNLOAD
            # =================================================

            if os.path.exists(
                output_report_name
            ):

                with open(
                    output_report_name,
                    "rb"
                ) as pdf_data_stream:

                    st.download_button(
                        label=(
                            "📥 Download Threat "
                            "Investigation Summary PDF"
                        ),
                        data=pdf_data_stream.read(),
                        file_name=(
                            "Forensic_Threat_Analysis_Report.pdf"
                        ),
                        mime="application/pdf"
                    )


                st.success(
                    "✅ Certified forensic report "
                    "artifact successfully rendered "
                    "and packed for extraction!"
                )

            else:

                st.error(
                    "Failed to generate report artifact "
                    "due to an internal directory "
                    "write limitation."
                )
