"""BiLSTM phishing classifier + an inference wrapper used by the notebook and the API.

This file is generated from notebooks/02_model_training.ipynb (%%writefile cell).
Edit it there and re-run the notebook so the notebook and the API stay in sync.
"""
import json
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.nn.utils.rnn import pack_padded_sequence, pad_packed_sequence

from .text import Vocab, clean_text, count_urls, tokenize


class BiLSTMClassifier(nn.Module):
    """Embedding -> BiLSTM -> masked mean+max pooling -> MLP head -> 1 logit.

    Output is a single logit; sigmoid(logit) = P(phishing). Trained with
    BCEWithLogitsLoss (sigmoid + binary cross-entropy in one numerically stable op).
    """

    def __init__(self, vocab_size, emb_dim=100, hidden_dim=64, num_layers=1,
                 dropout=0.3, pad_idx=0):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, emb_dim, padding_idx=pad_idx)
        self.emb_dropout = nn.Dropout(dropout)
        self.lstm = nn.LSTM(emb_dim, hidden_dim, num_layers=num_layers,
                            batch_first=True, bidirectional=True,
                            dropout=dropout if num_layers > 1 else 0.0)
        self.head = nn.Sequential(
            nn.Linear(hidden_dim * 2 * 2, 64),  # (fwd+bwd) x (mean+max)
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 1),
        )

    def forward(self, x, lengths):
        emb = self.emb_dropout(self.embedding(x))                       # (B, T, E)
        packed = pack_padded_sequence(emb, lengths.cpu(), batch_first=True,
                                      enforce_sorted=False)
        out, _ = self.lstm(packed)
        out, _ = pad_packed_sequence(out, batch_first=True,
                                     total_length=x.size(1))            # (B, T, 2H)
        mask = (torch.arange(x.size(1), device=x.device)[None, :]
                < lengths[:, None].to(x.device)).unsqueeze(-1)          # (B, T, 1)
        mean_pool = (out * mask).sum(1) / mask.sum(1).clamp(min=1)
        max_pool = out.masked_fill(~mask, -1e9).max(1).values
        return self.head(torch.cat([mean_pool, max_pool], dim=1)).squeeze(1)


def collate_ids(seqs, pad_idx=0):
    """Pad a list of id-lists into a batch tensor plus a lengths tensor."""
    lengths = torch.tensor([len(s) for s in seqs], dtype=torch.long)
    batch = torch.full((len(seqs), int(lengths.max())), pad_idx, dtype=torch.long)
    for i, s in enumerate(seqs):
        batch[i, : len(s)] = torch.tensor(s, dtype=torch.long)
    return batch, lengths


class PhishingDetector:
    """Loads the saved BiLSTM (and optional baseline) and serves predictions."""

    def __init__(self, model_dir):
        model_dir = Path(model_dir)
        self.config = json.loads((model_dir / "config.json").read_text(encoding="utf-8"))
        self.vocab = Vocab.load(model_dir / "vocab.json")
        self.max_len = self.config["max_len"]
        self.threshold = float(self.config.get("threshold", 0.5))
        self.device = torch.device("cpu")
        self.model = BiLSTMClassifier(len(self.vocab), **self.config["model_params"])
        state = torch.load(model_dir / "bilstm.pt", map_location=self.device)
        self.model.load_state_dict(state)
        self.model.eval()
        self.baseline = None
        baseline_path = model_dir / "baseline_tfidf_logreg.joblib"
        if baseline_path.exists():
            import joblib
            self.baseline = joblib.load(baseline_path)
            self.baseline_threshold = float(self.config.get("baseline_threshold", 0.5))

    # ---------- BiLSTM ----------
    @torch.no_grad()
    def _logits_from_tokens(self, token_lists, batch_size=256):
        logits = []
        for i in range(0, len(token_lists), batch_size):
            ids = [self.vocab.encode(t, self.max_len) for t in token_lists[i:i + batch_size]]
            x, lengths = collate_ids(ids)
            logits.append(self.model(x, lengths).numpy())
        return np.concatenate(logits) if logits else np.array([])

    def _proba_from_tokens(self, token_lists, batch_size=256):
        return 1.0 / (1.0 + np.exp(-self._logits_from_tokens(token_lists, batch_size)))

    def predict_proba(self, texts):
        """texts: list of already-cleaned strings -> P(phishing) for each."""
        return self._proba_from_tokens([tokenize(t) for t in texts])

    def explain(self, text, top_k=10):
        """Occlusion (leave-one-word-out) explanation.

        For each distinct word, remove every occurrence and measure how much the
        model's log-odds of phishing change. Log-odds are used instead of the raw
        probability because a probability of 0.9999 hardly moves when one word is
        removed (sigmoid saturation), while the log-odds still show the effect.
        Positive weight = the word pushes the email towards phishing.
        """
        tokens = tokenize(text)[: self.max_len]
        if not tokens:
            return []
        base = float(self._logits_from_tokens([tokens])[0])
        words = list(dict.fromkeys(tokens))[:200]
        variants = [[t for t in tokens if t != w] or ["<unk>"] for w in words]
        weights = base - self._logits_from_tokens(variants)
        order = np.argsort(-np.abs(weights))[:top_k]
        return [{"token": words[i], "weight": round(float(weights[i]), 4)} for i in order]

    # ---------- public API ----------
    def analyse(self, subject, body, model="bilstm", explain=True, top_k=10):
        text = clean_text(subject, body)
        if model == "baseline":
            if self.baseline is None:
                raise ValueError("Baseline model not available")
            prob = float(self.baseline.predict_proba([text])[0, 1])
            threshold = self.baseline_threshold
            tokens = self._baseline_explain(text, top_k) if explain else []
        else:
            prob = float(self.predict_proba([text])[0])
            threshold = self.threshold
            tokens = self.explain(text, top_k) if explain else []
        return {
            "label": "phishing" if prob >= threshold else "legitimate",
            "probability": round(prob, 4),
            "threshold": round(threshold, 4),
            "model": model,
            "top_tokens": tokens,
            "indicators": {
                "url_count": count_urls(f"{subject or ''} {body or ''}"),
                "word_count": len(tokenize(text)),
                "exclamation_marks": text.count("!"),
            },
        }

    def _baseline_explain(self, text, top_k=10):
        """For TF-IDF + LogReg: contribution = tfidf value x coefficient."""
        vec = self.baseline.named_steps["tfidf"]
        clf = self.baseline.named_steps["clf"]
        row = vec.transform([text]).tocoo()
        names = vec.get_feature_names_out()
        contrib = [(names[j], float(v * clf.coef_[0][j])) for j, v in zip(row.col, row.data)]
        contrib.sort(key=lambda t: -abs(t[1]))
        return [{"token": w, "weight": round(c, 4)} for w, c in contrib[:top_k]]
