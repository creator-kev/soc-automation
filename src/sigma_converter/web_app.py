"""FastAPI web app: serve a minimal Sigma rule generator UI and conversion API."""
from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from sigma_converter import CsvToSigmaConverter, DetectionRule, FieldMapping

app = FastAPI(title="Sigma Rule Generator")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_PATH = PROJECT_ROOT / "web" / "templates" / "index.html"


class ConvertRequest(BaseModel):
    title: str = Field(..., examples=["HTTP Admin Access"])
    rule_id: str | None = None
    level: str = Field(default="medium", examples=["low", "medium", "high", "critical"])
    log_format: Literal["csv", "jsonl"] = "csv"
    log_data: str = Field(..., examples=["client,request,status\\n10.0.0.1,/admin,200"])
    mappings: list[str] = Field(
        default_factory=list,
        examples=[["client:src_ip:ip", "request:request:url"]],
    )


class ConvertResponse(BaseModel):
    rule_yaml: str
    fields: list[str]


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    html = TEMPLATE_PATH.read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.post("/api/convert", response_model=ConvertResponse)
async def convert_api(payload: ConvertRequest) -> JSONResponse:
    try:
        mappings = _parse_mappings(payload.mappings)
        rule = _build_rule(payload.title, payload.rule_id, payload.level)
        converter = CsvToSigmaConverter(mappings=mappings)
        rendered = (
            converter.convert_csv(payload.log_data, rule)
            if payload.log_format == "csv"
            else converter.convert_jsonl(payload.log_data, rule)
        )
        return JSONResponse({"rule_yaml": rendered, "fields": rule.fields})
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/generate-id")
async def generate_id() -> JSONResponse:
    return JSONResponse({"id": uuid.uuid4().hex[:10]})


def _parse_mappings(raw: list[str] | None) -> list[FieldMapping] | None:
    if not raw:
        return None
    out: list[FieldMapping] = []
    for item in raw:
        parts = item.split(":")
        if len(parts) < 2:
            continue
        source = parts[0]
        sigma_field = parts[1]
        transform = parts[2] if len(parts) > 2 else "raw"
        out.append(FieldMapping(source=source, sigma_field=sigma_field, transform=transform))
    return out


def _build_rule(title: str, rule_id: str | None, level: str) -> DetectionRule:
    return DetectionRule(
        title=title,
        id=rule_id or title.lower().replace(" ", "-")[:32],
        description="Generated from SOC Automation Sigma Converter",
        author="soc-automation",
        date=datetime.now().date().isoformat(),
        level=level,
    )


def run() -> None:
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        log_level="info",
    )
