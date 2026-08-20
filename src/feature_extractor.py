import re
from urllib.parse import urlparse


def extract_url_features_v2(url):

    features = {}

    # Basic URL features
    features["url_length"] = len(url)

    features["num_letters"] = sum(
        c.isalpha()
        for c in url
    )

    features["num_digits"] = sum(
        c.isdigit()
        for c in url
    )

    # Special characters
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_underscores"] = url.count("_")
    features["num_slashes"] = url.count("/")
    features["num_question_marks"] = url.count("?")
    features["num_equal"] = url.count("=")
    features["num_at"] = url.count("@")
    features["num_ampersand"] = url.count("&")
    features["num_percent"] = url.count("%")
    features["num_colons"] = url.count(":")
    features["num_semicolons"] = url.count(";")
    features["num_double_slashes"] = url.count("//")

    # Ratios
    if len(url) > 0:

        features["digit_ratio"] = (
            features["num_digits"] / len(url)
        )

        features["letter_ratio"] = (
            features["num_letters"] / len(url)
        )

        special_chars = sum(
            not c.isalnum()
            for c in url
        )

        features["special_char_ratio"] = (
            special_chars / len(url)
        )

    else:

        features["digit_ratio"] = 0
        features["letter_ratio"] = 0
        features["special_char_ratio"] = 0

    # HTTPS
    features["is_https"] = int(
        url.lower().startswith("https://")
    )

    # Parse URL
    parsed = urlparse(url)

    domain = parsed.netloc.split(":")[0]
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # Domain
    features["domain_length"] = len(domain)

    features["domain_dot_count"] = (
        domain.count(".")
    )

    features["domain_has_hyphen"] = int(
        "-" in domain
    )

    features["domain_has_digits"] = int(
        any(
            c.isdigit()
            for c in domain
        )
    )

    # Path
    features["path_length"] = len(path)

    features["num_path_segments"] = len(
        [
            item
            for item in path.split("/")
            if item
        ]
    )

    # Query
    features["query_length"] = len(query)

    features["query_parameter_count"] = (
        len(query.split("&"))
        if query
        else 0
    )

    # Fragment
    features["fragment_length"] = len(fragment)

    features["has_fragment"] = int(
        bool(fragment)
    )

    # Subdomains
    features["num_subdomains"] = max(
        0,
        len(domain.split(".")) - 2
    )

    # IP address
    features["has_ip"] = int(
        bool(
            re.search(
                r"^(?:\d{1,3}\.){3}\d{1,3}$",
                domain
            )
        )
    )

    # Suspicious keywords
    suspicious_keywords = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "security",
        "password",
        "confirm",
        "bank",
        "paypal",
        "payment",
        "wallet",
        "credential",
        "authenticate"
    ]

    url_lower = url.lower()

    keyword_count = sum(
        keyword in url_lower
        for keyword in suspicious_keywords
    )

    features["suspicious_keyword_count"] = (
        keyword_count
    )

    features["has_suspicious_keyword"] = int(
        keyword_count > 0
    )

    return features