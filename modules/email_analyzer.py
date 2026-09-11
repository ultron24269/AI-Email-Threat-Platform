import re
import os
import imaplib
import email
from email import policy
from email.parser import BytesParser

def analyze_email(uploaded_file):
    """
    Analyze an uploaded .eml file or raw stream data 
    and extract important email information.
    """
    # Gracefully handle both raw network byte buffers and uploaded file payloads
    if hasattr(uploaded_file, 'read'):
        email_data = uploaded_file.read()
    else:
        email_data = uploaded_file

    # Parse email structure
    msg = BytesParser(policy=policy.default).parsebytes(email_data)

    # Basic information
    sender = msg.get("From", "Unknown")
    receiver = msg.get("To", "Unknown")
    subject = msg.get("Subject", "No Subject")
    date = msg.get("Date", "Unknown")
    reply_to = msg.get("Reply-To", "Not Available")
    message_id = msg.get("Message-ID", "Not Available")

    # Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body = part.get_content()
                except Exception:
                    body = ""
                break
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    # Extract URLs
    urls = re.findall(r'https?://[^\s<>"\']+', body)

    # Remove duplicate URLs
    urls = list(dict.fromkeys(urls))

    # Extract important headers
    headers = {}
    important_headers = [
        "From",
        "To",
        "Subject",
        "Date",
        "Reply-To",
        "Message-ID",
        "Return-Path",
        "Received",
        "Authentication-Results"
    ]

    for header in important_headers:
        values = msg.get_all(header)
        if values:
            headers[header] = values

    # Return analysis result
    return {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "date": date,
        "reply_to": reply_to,
        "message_id": message_id,
        "body": body,
        "urls": urls,
        "headers": headers
    }


def check_live_mailbox():
    """
    Connects to the mail server via IMAP, fetches UNSEEN incoming emails,
    and automatically forwards them to the AI pipeline for scanning.
    """
    # 1. Heartbeat Log: Shows up in the terminal drawer panel every 30 seconds
    print("[WATCHDOG LOG] ---> Firing background email server sync cycle...")
    
    # ⚠️ CONFIGURATION TARGETS: Change these strings to match your real credentials 
    # Or manage them securely using Streamlit Secrets / Environment variables.
    EMAIL_USER = os.getenv("WATCHDOG_EMAIL", "your-email@gmail.com")
    EMAIL_PASS = os.getenv("WATCHDOG_PASSWORD", "your-16-char-google-app-password")
    IMAP_SERVER = os.getenv("WATCHDOG_IMAP", "://gmail.com")

    detected_threats = []

    try:
        # 2. Open secure connection socket
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_USER, EMAIL_PASS)
        print("[WATCHDOG LOG] Authentication successful! Connected to mail gateway.")

        # Select target directory (Use "INBOX" or switch to "[Gmail]/Spam" for isolated link testing)
        mail.select("INBOX")

        # Query mailbox exclusively for UNREAD / UNSEEN items
        status, search_data = mail.search(None, "UNSEEN")
        
        if status != "OK":
            print("[WATCHDOG ERROR] Mailbox folder index search command failed.")
            return []

        # Parse message identification markers
        email_ids = search_data[0].split()
        print(f"[WATCHDOG LOG] Synchronized. Found {len(email_ids)} unread messages to evaluate.")

        # Batch pull only the latest 3 emails to prevent pipeline lags
        for e_id in email_ids[-3:]:
            # Fetch raw structural message body bytes
            fetch_status, fetch_data = mail.fetch(e_id, "(RFC822)")
            if fetch_status != "OK":
                continue

            raw_email_bytes = fetch_data[0][1]

            # Ingest raw email directly using the existing analyze_email function above
            analysis_output = analyze_email(raw_email_bytes)
            
            print(f"[WATCHDOG ALERT] Intercepted Subject: '{analysis_output['subject']}' | Found URLs: {len(analysis_output['urls'])}")
            detected_threats.append(analysis_output)

            # Optional optimization: Mark as read so it isn't repeatedly scanned next pulse
            # mail.store(e_id, '+FLAGS', '\\Seen')

        # Terminate network session links cleanly
        mail.close()
        mail.logout()
        print("[WATCHDOG LOG] Mail session closed down smoothly.")

    except Exception as connection_error:
        # 3. CRITICAL: Catches any hidden server blocks or bad passwords and logs them clearly
        print(f"[WATCHDOG CRITICAL ERROR] Pipeline execution broke down. Details: {connection_error}")

    return detected_threats
