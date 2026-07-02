from urllib.parse import urlparse
import re
import tldextract
import pandas as pd

def clean_url(url):

    try:
        if pd.isna(url):
            return None
        url = str(url).strip()
        if len(url) == 0:
            return None
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        urlparse(url)
        return url
    
    except:
        return None
    
SUSPICIOUS_TLDS = {
    "xyz","top","click","work","loan",
    "zip","country","gq","cf","tk","ml"
    }

BRANDS = {
    "google", "amazon", "paypal", "microsoft",
    "apple", "netflix", "facebook", "instagram",
    "github", "steam", "discord", "dropbox",
    "reddit", "youtube", "linkedin",
    "twitter", "x", "whatsapp",
    "telegram", "spotify", "adobe",
    "icloud", "office", "outlook",
    "gmail", "steam", "epicgames"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "secure",
    "account", "update", "bank",
    "paypal", "password", "signin",
    "auth", "confirm", "support",
    "free", "billing", "invoice",
    "payment", "recovery", "unlock"
}

KNOWN_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "maps.google.com", "google.co.in",
    "amazon.com", "amazon.in", "flipkart.com", "ebay.com", "walmart.com",
    "github.com", "stackoverflow.com", "python.org", "pypi.org", "gitlab.com",
    "bitbucket.org", "npmjs.com", "mozilla.org", "w3schools.com",
    "reddit.com", "discord.com", "linkedin.com", "facebook.com", "instagram.com",
    "x.com", "twitter.com", "threads.net", "snapchat.com", "pinterest.com",
    "microsoft.com", "office.com", "live.com", "outlook.com", "skype.com",
    "apple.com", "icloud.com", "support.apple.com", "developer.apple.com",
    "netflix.com", "spotify.com", "steamcommunity.com", "steampowered.com",
    "epicgames.com", "ea.com", "riotgames.com", "ubisoft.com",
    "paypal.com", "stripe.com", "visa.com", "mastercard.com", "americanexpress.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com",
    "wikipedia.org", "wiktionary.org", "britannica.com", "archive.org",
    "medium.com", "quora.com", "substack.com", "wordpress.com",
    "openai.com", "anthropic.com", "huggingface.co", "kaggle.com",
    "coursera.org", "udemy.com", "edx.org", "mit.edu",
    "yahoo.com", "bing.com", "duckduckgo.com", "yandex.com",
    "cloudflare.com", "oracle.com", "ibm.com", "intel.com",
    "samsung.com", "oneplus.com", "xiaomi.com", "oppo.com", "vivo.com",
    "realme.com", "lenovo.com", "hp.com", "dell.com",
    "bbc.com", "reuters.com", "nytimes.com", "theguardian.com",
    "cnn.com", "forbes.com", "techcrunch.com", "arstechnica.com",
    "airbnb.com", "booking.com", "tripadvisor.com", "uber.com",
    "ola.com", "zomato.com", "swiggy.com", "makemytrip.com"
}


def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    suffix = ext.suffix
    subdomain = ext.subdomain
    domain = ext.domain
    registered_domain_length = len(domain)

    suspicious_tld = (
        1 if suffix in SUSPICIOUS_TLDS
        else 0
    )

    suspicious_keyword_count = sum(
        word in url.lower()
        for word in SUSPICIOUS_WORDS
    )
    
    brand_in_subdomain = any(
        brand in subdomain.lower()
        for brand in BRANDS
    )

    brand_count = sum(
        brand in url.lower()
        for brand in BRANDS
    )

    subdomain_count = (
        len(subdomain.split("."))
        if subdomain else 0
    )

    registered_domain = f"{domain}.{suffix}"
    is_known_domain = int(
        registered_domain in KNOWN_DOMAINS
    )

    num_letters = sum(c.isalpha() for c in url)
    num_digits = sum(c.isdigit() for c in url)
    num_hyphens = url.count("-")
    url_length = len(url)

    is_root_domain = 1 if parsed.path in ("", "/") else 0

    digit_ratio = (
        num_digits / url_length
        if url_length > 0 else 0
    )

    hyphen_ratio = (
        num_hyphens / url_length
        if url_length > 0 else 0
    )

    return {
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_digits": sum(c.isdigit() for c in url),

        # "num_slashes": url.count("/"),
        "num_questionmarks": url.count("?"),
        "num_equals": url.count("="),
        "num_ampersands": url.count("&"),

        "has_https": 1 if url.startswith("https") else 0,
        "has_http": 1 if url.startswith("http") else 0,

        "has_at": 1 if "@" in url else 0,

        "has_ip": 1 if re.search(
            r"\d+\.\d+\.\d+\.\d+",
            url
        ) else 0,

        "subdomain_count": subdomain_count,
        "query_length": len(parsed.query),
        "special_chars": sum(
            not c.isalnum()
            for c in url
        ),

        # "is_root_domain": is_root_domain,
        # "brand_count": brand_count,
        "known_domain": is_known_domain,
        "brand_in_subdomain": int(brand_in_subdomain),
        "regi_domain_len": registered_domain_length,
        "suspicious_keyword_count": suspicious_keyword_count,

        "num_letters": num_letters,
        "digit_ratio": digit_ratio,
        "hyphen_ratio": hyphen_ratio,
        "contains_sus_tld": suspicious_tld,
    }