FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN --mount=type=secret,id=corporate_ca,required=false \
    if [ -f /run/secrets/corporate_ca ] && [ -s /run/secrets/corporate_ca ]; then \
      apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
      cp /run/secrets/corporate_ca /usr/local/share/ca-certificates/corporate-ca.crt && \
      update-ca-certificates && rm -rf /var/lib/apt/lists/*; \
    fi
COPY pyproject.toml README.md ./
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
RUN pip install --no-cache-dir "setuptools>=68" && pip install --no-cache-dir --no-build-isolation .
RUN mkdir -p /app/data /app/workspace
EXPOSE 8080
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8080"]
