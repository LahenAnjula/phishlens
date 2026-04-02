import re
import joblib
import tldextract
import Levenshtein
from scipy.stats import entropy

from trusted_store import load_dynamic_trusted

# =========================================================
# LOAD GLOBAL TRUSTED DOMAINS
# =========================================================

# This should be generated during training from Tranco or another large benign list
trusted_domains = set(joblib.load("trusted_domains.pkl"))

# Offline TLD extractor
extractor = tldextract.TLDExtract(suffix_list_urls=None)

# =========================================================
# FEATURE LIST
# =========================================================

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "digit_count",
    "hyphen_count",
    "special_char_count",
    "has_https",
    "subdomain_count",
    "entropy",
    "trusted_domain",
    "rare_domain",
    "impersonation_flag",
    "has_login",
    "has_verify",
    "has_secure",
    "has_account"
]

# =========================================================
# URL NORMALIZATION
# =========================================================

def normalize_url(url: str) -> str:
    url = str(url).strip().lower()
    url = url.replace(" ", "")

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Remove only leading www while preserving scheme
    url = re.sub(r"^(https?://)www\.", r"\1", url)

    return url

# =========================================================
# HELPER FUNCTIONS
# =========================================================

def safe_entropy(text: str) -> float:
    if not text:
        return 0.0

    probs = [text.count(c) / len(text) for c in set(text)]
    return float(entropy(probs))


def refresh_dynamic_trusted() -> set[str]:
    return load_dynamic_trusted()


def extract_root_domain(url: str) -> str:
    url = normalize_url(url)
    ext = extractor(url)

    domain = ext.domain.lower()
    suffix = ext.suffix.lower()

    return f"{domain}.{suffix}" if suffix else domain


def is_trusted_root(root: str, dynamic_trusted: set[str]) -> bool:
    return root in trusted_domains or root in dynamic_trusted


def strong_impersonation(root: str, dynamic_trusted: set[str]) -> int:
    """
    Detect if the root domain is very similar to a trusted domain.
    """
    if is_trusted_root(root, dynamic_trusted):
        return 0

    trusted_pool = trusted_domains.union(dynamic_trusted)

    for legit in trusted_pool:
        if abs(len(legit) - len(root)) > 2:
            continue

        if Levenshtein.distance(root, legit) <= 2:
            return 1

    return 0

# =========================================================
# MAIN FEATURE EXTRACTION
# =========================================================

def extract_features(url: str) -> dict:
    dynamic_trusted = refresh_dynamic_trusted()

    url = normalize_url(url)
    ext = extractor(url)

    domain = ext.domain.lower()
    suffix = ext.suffix.lower()
    root = f"{domain}.{suffix}" if suffix else domain

    features = dict.fromkeys(FEATURE_COLUMNS, 0)

    # Basic lexical / structural features
    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["digit_count"] = sum(c.isdigit() for c in domain)
    features["hyphen_count"] = domain.count("-")
    features["special_char_count"] = len(re.findall(r"[!@#$%^&*(),?\":{}|<>]", url))
    features["has_https"] = int(url.startswith("https://"))
    features["subdomain_count"] = ext.subdomain.count(".") + 1 if ext.subdomain else 0
    features["entropy"] = safe_entropy(domain)

    # Trust / rarity / impersonation
    features["trusted_domain"] = int(is_trusted_root(root, dynamic_trusted))
    features["rare_domain"] = int(not is_trusted_root(root, dynamic_trusted))
    features["impersonation_flag"] = strong_impersonation(root, dynamic_trusted)

    # Phishing-related keywords
    features["has_login"] = int("login" in url)
    features["has_verify"] = int("verify" in url)
    features["has_secure"] = int("secure" in url)
    features["has_account"] = int("account" in url)

    return features