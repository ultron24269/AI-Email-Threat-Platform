import re
from email import policy
from email.parser import BytesParser


def analyze_email(uploaded_file):
    """
    Analyze an uploaded .eml file and extract
    important email information.
    """

    # Read email file
    email_data = uploaded_file.read()

    # Parse email
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
    urls = re.findall(
        r'https?://[^\s<>"\']+',
        body
    )

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
