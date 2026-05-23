"""
AutonomSOC Backend — Entry point
Run: python main.py   OR   uvicorn api.routes:app --reload --port 8000
"""
import uvicorn
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from api.routes import app  # noqa

if __name__ == "__main__":
    uvicorn.run(
        "api.routes:app",
        # host="0.0.0.0",
        host="127.0.0.1",
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("ENV", "development") == "development",
        log_level="info",
    )
