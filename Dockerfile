FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app
WORKDIR /app
COPY app/requirements.txt /tmp/requirements-app.txt
RUN pip install -r /tmp/requirements-app.txt

FROM base AS app
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /app/logs /data \
    && chown app:app /app/logs /data
COPY app/lab01 /app/lab01
USER app
EXPOSE 8000
CMD ["uvicorn", "lab01.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]

FROM base AS tests
COPY tests/requirements.txt /tmp/requirements-tests.txt
RUN pip install -r /tmp/requirements-tests.txt
COPY app/lab01 /app/lab01
COPY tests /app/tests
CMD ["pytest", "-p", "no:cacheprovider", "-v", "tests"]
