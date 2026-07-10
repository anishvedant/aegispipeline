# Triage API image: current slim base, pinned deps, non-root.
FROM python:3.12-slim

RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.32.1 && \
    useradd --create-home --shell /usr/sbin/nologin appuser
WORKDIR /app
COPY app.py .
USER appuser
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
