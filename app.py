"""FastAPI routes and application startup for the EC2 Resource Analyzer."""

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from analyzer import AnalysisError, analyze_server

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="EC2 Resource Analyzer")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


class AnalyzeRequest(BaseModel):
    host: str
    username: str
    port: int = Field(default=22, ge=1, le=65535)
    use_sudo: bool = False


@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest):
    try:
        result = analyze_server(payload.host, payload.username, payload.port, payload.use_sudo)
        return JSONResponse(content=result)
    except AnalysisError as e:
        return JSONResponse(
            status_code=502,
            content={"error": True, "title": e.title, "reason": e.reason, "hints": e.hints},
        )
    except Exception as e:  # noqa: BLE001 - last-resort friendly error, never leak key contents
        return JSONResponse(
            status_code=500,
            content={"error": True, "title": "Unexpected Error", "reason": str(e), "hints": []},
        )
