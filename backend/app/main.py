"""Decoy Desk API: receives checks and orchestrates the three layers (who sent it, static read, decoy machine)."""
from fastapi import FastAPI

app = FastAPI(title="Decoy Desk", version="0.1.0")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}
