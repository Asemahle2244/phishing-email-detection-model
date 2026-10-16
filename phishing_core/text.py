"""Text cleaning, tokenisation and vocabulary for the phishing email detector.

This file is generated from notebooks/02_model_training.ipynb (%%writefile cell).
Edit it there and re-run the notebook so the notebook and the API stay in sync.
"""
import html
import json
import re
from collections import Counter
from pathlib import Path

URL_RE = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
HTML_TAG_RE = re.compile(r"<[^>]+>")
NUM_RE = re.compile(r"\b\d+(?:[.,]\d+)*\b")
NON_WORD_RE = re.compile(r"[^a-z0-9$!?%\s]")
SPACE_RE = re.compile(r"\s+")

PAD, UNK = "<pad>", "<unk>"


def clean_text(subject, body) -> str:
    """Combine subject + body and normalise them into a single lowercase string.

    URLs, e-mail addresses and numbers are replaced with placeholder tokens so the
    model learns *that* a link is present rather than memorising specific domains.
    """
    subject = "" if subject is None or subject != subject else str(subject)  # handles NaN
    body = "" if body is None or body != body else str(body)
    text = f"{subject} {body}"
    text = html.unescape(text)
    text = HTML_TAG_RE.sub(" ", text)
    text = URL_RE.sub(" urltoken ", text)
    text = EMAIL_RE.sub(" emailtoken ", text)
    text = text.lower()
    text = NUM_RE.sub(" numtoken ", text)
    text = NON_WORD_RE.sub(" ", text)
    # keep ! ? $ % as separate tokens - they are strong spam/phishing signals
    text = re.sub(r"([$!?%])", r" \1 ", text)
    return SPACE_RE.sub(" ", text).strip()


def tokenize(text: str) -> list:
    return text.split()


def count_urls(text) -> int:
    return len(URL_RE.findall(str(text or "")))


class Vocab:
    """Word -> integer index mapping, built on the TRAINING set only (no leakage)."""

    def __init__(self, itos):
        self.itos = list(itos)
        self.stoi = {w: i for i, w in enumerate(self.itos)}

    @classmethod
    def build(cls, token_lists, max_size=25000, min_freq=2):
        counts = Counter(t for toks in token_lists for t in toks)
        words = [w for w, c in counts.most_common() if c >= min_freq][: max_size - 2]
        return cls([PAD, UNK] + words)

    def __len__(self):
        return len(self.itos)

    @property
    def pad_idx(self):
        return 0

    @property
    def unk_idx(self):
        return 1

    def encode(self, tokens, max_len=300):
        ids = [self.stoi.get(t, 1) for t in tokens[:max_len]]
        return ids if ids else [1]  # never return an empty sequence

    def save(self, path):
        Path(path).write_text(json.dumps(self.itos), encoding="utf-8")

    @classmethod
    def load(cls, path):
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))
