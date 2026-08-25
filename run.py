r"""啟動 BaselineGuard:Web UI 埠取自設定(預設 8073)。

用法:.\.venv\Scripts\python.exe run.py
Agent API(預設 8074)由 app.main 的 lifespan 於同程序內一併啟動。
"""
import uvicorn

from app.config import settings

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.web_port)
