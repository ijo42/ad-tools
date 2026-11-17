# Образ веб-интерфейса AD Toolkit (FastAPI + Vue 3, вендорен в webui/static).
FROM python:3.12-slim

WORKDIR /app
COPY adtool/ /app/adtool/
COPY webui/ /app/webui/
COPY ingest.py submitter.py web.py ./
RUN pip install --no-cache-dir fastapi uvicorn pyyaml

# команды задаёт docker-compose.yml
