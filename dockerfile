FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TERM=xterm-256color

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY soc_sentinel.py .

ENTRYPOINT ["python", "/app/soc_sentinel.py"]
