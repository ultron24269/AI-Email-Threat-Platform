import os
import sys

# Inserts the absolute root directory path into Python's search path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from models.url_phishing_model import predict_url


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "password",
    "secure",
    "security",
    "update",
    "payment",
    "confirm",
    "bank",
    "wallet",
    "signin",
    "credential",
    "unlock",
    "suspended",
    "invoice",
    "free",
    "gift"
]


def get_domain(url):
    """
    Extract hostname/domain from URL.
    """

    try:
        parsed = urlparse(url)

        return (
            parsed.hostname
            or ""
        ).lower()

    except Exception:
        return ""


def is_ip_address(hostname):
    """
    Check whether hostname is an IP address.
    """

    try:
        ipaddress.ip_address(
            hostname
        )

        return True

    except ValueError:
        return False


def count_subdomains(domain):
    """
    Estimate number of subdomain levels.
    """

    if not domain:
        return 0

    if is_ip_address(domain):
        return 0

    parts = domain.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def has_suspicious_keyword(url):
    """
    Detect phishing-related words.
    """

    url_lower = url.lower()

    found = [
        word
        for word in SUSPICIOUS_WORDS
        if word in url_lower
    ]

    return found


def check_dns(domain):
    """
    Check whether the domain resolves through DNS.
    """

    if not domain:
        return False

    if is_ip_address(domain):
        return True

    try:
        socket.gethostbyname(
            domain
        )

        return True

    except Exception:
        return False


def check_certificate(url):
    """
    Inspect the HTTPS certificate.

    Returns certificate information.
    """

    result = {
        "certificate_available": False,
        "certificate_valid": False,
        "certificate_expired": False,
        "hostname_match": False,
        "certificate_issuer": "Not Available",
        "certificate_subject": "Not Available",
        "certificate_valid_from": "Not Available",
        "certificate_valid_until": "Not Available",
        "certificate_days_remaining": -1,
        "tls_version": "Not Available",
        "certificate_error": ""
    }

    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        result["certificate_error"] = (
            "HTTPS is not enabled."
        )

        return result

    hostname = parsed.hostname

    if not hostname:
        result["certificate_error"] = (
            "Hostname not available."
        )

        return result

    port = parsed.port or 443

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_sock:

                certificate = (
                    secure_sock.getpeercert()
                )

                result[
                    "certificate_available"
                ] = True

                result[
                    "certificate_valid"
                ] = True

                result[
                    "hostname_match"
                ] = True

                result[
                    "tls_version"
                ] = (
                    secure_sock.version()
                    or "Unknown"
                )

                subject = dict(
                    item[0]
                    for item in certificate.get(
                        "subject",
                        []
                    )
                )

                issuer = dict(
                    item[0]
                    for item in certificate.get(
                        "issuer",
                        []
                    )
                )

                result[
                    "certificate_subject"
                ] = subject.get(
                    "commonName",
                    "Not Available"
                )

                result[
                    "certificate_issuer"
                ] = issuer.get(
                    "commonName",
                    "Not Available"
                )

                not_before = certificate.get(
                    "notBefore"
                )

                not_after = certificate.get(
                    "notAfter"
                )

                if not_before:
                    result[
                        "certificate_valid_from"
                    ] = not_before

                if not_after:
                    result[
                        "certificate_valid_until"
                    ] = not_after

                    expiry = datetime.strptime(
                        not_after,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(
                        tzinfo=timezone.utc
                    )

                    now = datetime.now(
                        timezone.utc
                    )

                    days = (
                        expiry - now
                    ).days

                    result[
                        "certificate_days_remaining"
                    ] = days

                    if days < 0:
                        result[
                            "certificate_expired"
                        ] = True

                        result[
                            "certificate_valid"
                        ] = False

        return result

    except ssl.CertificateError as error:

        result[
            "certificate_error"
        ] = (
            f"Certificate validation error: "
            f"{error}"
        )

        result[
            "hostname_match"
        ] = False

        return result

    except Exception as error:

        result[
            "certificate_error"
        ] = str(error)

        return result


def check_redirects(url):
    """
    Safely inspect HTTP redirects.

    Redirect targets are not executed as code.
    """

    try:

        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            stream=True,
            headers={
                "User-Agent":
                "AI-Email-Threat-Platform/1.0"
            }
        )

        history = response.history

        redirect_urls = [
            item.url
            for item in history
        ]

        final_url = response.url

        response.close()

        return {
            "redirect_count": len(
                history
            ),
            "redirect_urls": redirect_urls,
            "final_url": final_url
        }

    except Exception as error:

        return {
            "redirect_count": -1,
            "redirect_urls": [],
            "final_url": url,
            "redirect_error": str(error)
        }


def extract_features(url):
    """
    Extract all features required by
    the ML model.
    """

    parsed = urlparse(url)

    domain = get_domain(url)

    path = parsed.path or ""

    suspicious_words = (
        has_suspicious_keyword(url)
    )

    certificate = check_certificate(
        url
    )

    dns_available = check_dns(
        domain
    )

    redirect_data = check_redirects(
        url
    )

    features = {
        "url_length": len(url),

        "domain_length": len(domain),

        "path_length": len(path),

        "subdomain_count":
            count_subdomains(domain),

        "has_https":
            int(
                parsed.scheme.lower()
                == "https"
            ),

        "has_ip_address":
            int(
                is_ip_address(domain)
            ),

        "has_at_symbol":
            int("@" in url),

        "has_dash_in_domain":
            int("-" in domain),

        "has_suspicious_keyword":
            int(
                len(suspicious_words) > 0
            ),

        "has_punycode":
            int(
                "xn--" in domain
            ),

        "has_port":
            int(
                parsed.port is not None
            ),

        "certificate_valid":
            int(
                certificate[
                    "certificate_valid"
                ]
            ),

        "certificate_expired":
            int(
                certificate[
                    "certificate_expired"
                ]
            ),

        "hostname_match":
            int(
                certificate[
                    "hostname_match"
                ]
            ),

        "certificate_days_remaining":
            certificate[
                "certificate_days_remaining"
            ],

        "redirect_count":
            max(
                0,
                redirect_data[
                    "redirect_count"
                ]
            ),

        "dns_available":
            int(dns_available)
    }

    return (
        features,
        certificate,
        redirect_data,
        suspicious_words
    )


def analyze_url(url):
    """
    Complete AI-powered URL analysis.
    """

    url = url.strip()

    if not url:
        return {
            "url": url,
            "risk": "INVALID",
            "score": 0,
            "phishing_probability": 0,
            "ai_prediction": "INVALID",
            "reasons": [
                "Empty URL."
            ]
        }

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "http://" + url

    try:

        (
            features,
            certificate,
            redirects,
            suspicious_words
        ) = extract_features(url)

        ai_result = predict_url(
            features
        )

        probability = (
            ai_result[
                "phishing_probability"
            ]
        )

        reasons = []

        if not features[
            "has_https"
        ]:
            reasons.append(
                "Website does not use HTTPS."
            )

        if features[
            "has_ip_address"
        ]:
            reasons.append(
                "URL uses a direct IP address."
            )

        if features[
            "has_at_symbol"
        ]:
            reasons.append(
                "URL contains @ character."
            )

        if suspicious_words:
            reasons.append(
                "Suspicious keyword(s): "
                + ", ".join(
                    suspicious_words
                )
            )

        if features[
            "has_punycode"
        ]:
            reasons.append(
                "Domain uses Punycode."
            )

        if features[
            "subdomain_count"
        ] >= 3:
            reasons.append(
                "Large number of subdomains."
            )

        if (
            certificate[
                "certificate_available"
            ]
        ):

            if certificate[
                "certificate_expired"
            ]:
                reasons.append(
                    "TLS certificate is expired."
                )

            if not certificate[
                "hostname_match"
            ]:
                reasons.append(
                    "Certificate hostname "
                    "does not match the site."
                )

            if (
                certificate[
                    "certificate_days_remaining"
                ] >= 0
                and
                certificate[
                    "certificate_days_remaining"
                ] < 15
            ):
                reasons.append(
                    "TLS certificate expires "
                    "soon."
                )

        else:

            if features[
                "has_https"
            ]:
                reasons.append(
                    "TLS certificate could "
                    "not be validated."
                )

        if redirects[
            "redirect_count"
        ] >= 3:
            reasons.append(
                "Multiple redirects detected."
            )

        if not features[
            "dns_available"
        ]:
            reasons.append(
                "Domain does not resolve "
                "through DNS."
            )

        if probability >= 70:

            risk = "HIGH RISK"

        elif probability >= 40:

            risk = "SUSPICIOUS"

        else:

            risk = "LOW RISK"

        ai_prediction = (
            "PHISHING"
            if ai_result[
                "prediction"
            ] == 1
            else "LEGITIMATE"
        )

        return {
            "url": url,

            "risk": risk,

            "score": round(
                probability
            ),

            "phishing_probability":
                probability,

            "ai_prediction":
                ai_prediction,

            "reasons":
                reasons or [
                    "No major suspicious "
                    "characteristics detected."
                ],

            "features":
                features,

            "certificate":
                certificate,

            "redirects":
                redirects,

            "dns_available":
                bool(
                    features[
                        "dns_available"
                    ]
                )
        }

    except Exception as error:

        return {
            "url": url,
            "risk": "ANALYSIS ERROR",
            "score": 0,
            "phishing_probability": 0,
            "ai_prediction": "UNKNOWN",
            "reasons": [
                str(error)
            ]
        }


def analyze_urls(urls):

    return [
        analyze_url(url)
        for url in urls
        if url
    ]
