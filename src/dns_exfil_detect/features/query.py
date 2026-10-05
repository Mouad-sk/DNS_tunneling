"""Lexical and statistical features for a single DNS query."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from dns_exfil_detect.models import DnsQueryEvent, QueryFeatures

_HEXISH = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_BASE32ISH = re.compile(r"^[a-z2-7]+$", re.IGNORECASE)
_BASE64ISH = re.compile(r"^[A-Za-z0-9+/]+$")

PUBLIC_SUFFIX_HINTS = frozenset(
    {"co.uk", "com.au", "co.jp", "com.br", "co.za", "com.mx", "co.in"}
)


def parent_domain(fqdn: str) -> str:
    """Approximate registrable domain (eTLD+1) without an OS-specific PSL library."""
    labels = [p for p in fqdn.lower().strip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in PUBLIC_SUFFIX_HINTS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def subdomain_labels(fqdn: str) -> list[str]:
    """Labels to the left of the parent domain."""
    parent = parent_domain(fqdn)
    fqdn_n = fqdn.lower().strip(".")
    if fqdn_n == parent or not fqdn_n.endswith(parent):
        return []
    prefix = fqdn_n[: -len(parent)].strip(".")
    return [p for p in prefix.split(".") if p]


def shannon_entropy(text: str) -> float:
    """Shannon entropy (bits) of a string; 0.0 for empty input."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def longest_label_length(fqdn: str) -> int:
    labels = [p for p in fqdn.split(".") if p]
    return max((len(p) for p in labels), default=0)


def character_class_ratios(text: str) -> tuple[float, float, float, float]:
    """Return (letter, digit, hyphen, other) ratios in ``text``."""
    if not text:
        return 0.0, 0.0, 0.0, 0.0
    letters = digits = hyphens = other = 0
    for char in text:
        if char.isalpha():
            letters += 1
        elif char.isdigit():
            digits += 1
        elif char == "-":
            hyphens += 1
        else:
            other += 1
    n = len(text)
    return letters / n, digits / n, hyphens / n, other / n


def encoding_likeness(text: str) -> float:
    """Score 0-1 for base32/base64/hex-like labels commonly used in DNS tunnels.

    This is a heuristic for *detection* of encoded payloads in names, not an encoder.
    """
    if not text:
        return 0.0
    compact = text.replace(".", "").replace("-", "")
    if len(compact) < 8:
        return 0.0
    _, digit_ratio, _, other_ratio = character_class_ratios(compact)
    entropy = shannon_entropy(compact.lower())
    charset_hit = 0.0
    if _HEXISH.match(compact) and len(compact) >= 16:
        charset_hit = 0.9
    elif _BASE32ISH.match(compact.lower()) and len(compact) >= 16:
        charset_hit = 0.8
    elif _BASE64ISH.match(compact) and len(compact) >= 16:
        charset_hit = 0.75
    mixed = 0.0
    if digit_ratio >= 0.2 and entropy >= 3.2:
        mixed = min(1.0, (digit_ratio + entropy / 5.0) / 2.0)
    return min(1.0, max(charset_hit, mixed) + 0.15 * other_ratio)


class NgramModel:
    """Character n-gram log-likelihood model trained on legitimate domains."""

    def __init__(self, n: int = 3, smoothing: float = 1.0) -> None:
        self.n = n
        self.smoothing = smoothing
        self.counts: Counter[str] = Counter()
        self.total = 0.0

    def fit(self, domains: list[str]) -> None:
        self.counts.clear()
        self.total = 0.0
        for domain in domains:
            padded = f"{'#' * (self.n - 1)}{domain.lower()}#"
            for i in range(len(padded) - self.n + 1):
                gram = padded[i : i + self.n]
                self.counts[gram] += 1
                self.total += 1
        if self.total <= 0:
            self.total = 1.0

    def score(self, text: str) -> float:
        """Average log10 probability of n-grams (higher = more like the corpus)."""
        if not text:
            return 0.0
        padded = f"{'#' * (self.n - 1)}{text.lower()}#"
        vocab = max(len(self.counts), 1)
        logs: list[float] = []
        for i in range(len(padded) - self.n + 1):
            gram = padded[i : i + self.n]
            num = self.counts.get(gram, 0) + self.smoothing
            den = self.total + self.smoothing * vocab
            logs.append(math.log10(num / den))
        if not logs:
            return 0.0
        return sum(logs) / len(logs)

    def anomaly(self, text: str, benign_floor: float = -2.2) -> float:
        """Map log-likelihood to 0-1 anomaly (1 = unlike legitimate domains)."""
        ll = self.score(text)
        return min(1.0, max(0.0, (benign_floor - ll) / 2.0))


def load_domain_list(path: str) -> list[str]:
    file_path = Path(path)
    if not file_path.is_file():
        return []
    domains: list[str] = []
    for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            parts = line.split(",")
            line = parts[-1].strip()
        domains.append(line.lower().strip("."))
    return domains


def extract_query_features(
    event: DnsQueryEvent,
    ngram: NgramModel,
    top_domains: set[str],
) -> QueryFeatures:
    """Compute per-query features for one DNS transaction."""
    fqdn = event.fqdn.lower().strip(".")
    subs = subdomain_labels(fqdn)
    sub_text = ".".join(subs)
    target = sub_text if sub_text else fqdn
    letter, digit, hyphen, other = character_class_ratios(target.replace(".", ""))
    parent = parent_domain(fqdn)
    in_top = parent in top_domains or fqdn in top_domains
    return QueryFeatures(
        timestamp=event.timestamp,
        src_ip=event.src_ip,
        fqdn=fqdn,
        parent_domain=parent,
        record_type=event.record_type.upper(),
        response_code=event.response_code.upper(),
        response_size=event.response_size,
        fqdn_length=len(fqdn),
        longest_label_length=longest_label_length(fqdn),
        label_count=len([p for p in fqdn.split(".") if p]),
        shannon_entropy=shannon_entropy(target.replace(".", "")),
        letter_ratio=letter,
        digit_ratio=digit,
        hyphen_ratio=hyphen,
        other_ratio=other,
        encoding_likeness=encoding_likeness(target),
        ngram_score=ngram.score(fqdn),
        is_nxdomain=event.response_code.upper() == "NXDOMAIN",
        in_top_list=in_top,
    )
