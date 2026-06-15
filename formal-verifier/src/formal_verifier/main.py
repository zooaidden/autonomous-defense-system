from datetime import UTC, datetime

from fastapi import FastAPI

from formal_verifier.engine import StrategyVerifier
from formal_verifier.models import DefenseStrategy, VerificationResult

app = FastAPI(title="formal-verifier", version="0.2.0")
verifier = StrategyVerifier()


@app.get("/health")
def health() -> dict:
    return {"status": "UP", "service": "formal-verifier", "time": datetime.now(UTC).isoformat()}


@app.post("/verify")
def verify(strategy: DefenseStrategy) -> VerificationResult:
    return verifier.verify(strategy)

