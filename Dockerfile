# Container for hosting the phishing detection API (bonus: model hosting).
# Build:  docker build -t phishing-api .
# Run:    docker run -p 8000:8000 phishing-api   ->  http://localhost:8000/docs
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# CPU-only PyTorch keeps the image small (~1 GB instead of ~5 GB)
COPY requirements-api.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
 && pip install --no-cache-dir -r requirements-api.txt

COPY phishing_core/ phishing_core/
COPY api/ api/
COPY models/ models/

EXPOSE 8000
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
