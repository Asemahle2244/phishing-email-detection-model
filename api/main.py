"""FastAPI service exposing the phishing email detector.

Run from the project root:
    uvicorn api.main:app --reload
Then open http://127.0.0.1:8000/docs for the interactive Swagger UI.
"""
import os
import sys
from contextlib import asynccontextmanager
import time
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phishing_core.model import PhishingDetector  # noqa: E402

MODEL_DIR = Path(os.environ.get("MODEL_DIR", ROOT / "models"))

detector: PhishingDetector | None = None
load_error: str | None = None


@asynccontextmanager
async def lifespan(_app):
    """Load the model once when the server starts."""
    global detector, load_error
    try:
        detector = PhishingDetector(MODEL_DIR)
    except Exception as exc:  # keep the API up so /health can report the problem
        load_error = f"{type(exc).__name__}: {exc}"
    yield


app = FastAPI(
    title="Phishing Email Detector API",
    description="ITRI625 project: BiLSTM + TF-IDF/LogReg phishing email classifier with word-level explanations.",
    version="1.0.0",
    lifespan=lifespan,
)
# Allow the desktop app, Swagger UI and the React frontend (Vite dev server) to call the API
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class EmailIn(BaseModel):
    subject: str = Field("", max_length=1000, examples=["Your account has been suspended"])
    body: str = Field(..., min_length=1, max_length=200_000,
                      examples=["Dear customer, verify your password at http://secure-login.example.com"])
    model: Literal["bilstm", "baseline"] = "bilstm"
    explain: bool = True
    top_k: int = Field(10, ge=1, le=30)


class TokenWeight(BaseModel):
    token: str
    weight: float


class PredictionOut(BaseModel):
    label: Literal["phishing", "legitimate"]
    probability: float
    threshold: float
    model: str
    top_tokens: list[TokenWeight]
    indicators: dict
    latency_ms: float


def get_detector() -> PhishingDetector:
    if detector is None:
        raise HTTPException(503, f"Model not loaded ({load_error}). Run the training notebook first.")
    return detector


@app.get("/")
def root():
    return {"service": "phishing-email-detector", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health():
    if detector is None:
        return {"status": "error", "detail": load_error}
    cfg = detector.config
    return {
        "status": "ok",
        "models": ["bilstm"] + (["baseline"] if detector.baseline is not None else []),
        "threshold": detector.threshold,
        "best_epoch": cfg.get("best_epoch"),
        "trained_on": cfg.get("trained_on"),
        "trained_at": cfg.get("trained_at"),
        "test_metrics": cfg.get("test_metrics"),
    }


@app.post("/predict", response_model=PredictionOut)
def predict(email: EmailIn):
    det = get_detector()
    t0 = time.perf_counter()
    try:
        result = det.analyse(email.subject, email.body, model=email.model,
                             explain=email.explain, top_k=email.top_k)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result
