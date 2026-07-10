FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app app

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --upgrade pip==26.1.2 \
    && python -m pip install .

RUN mkdir -p /data/uploads /data/audit \
    && chown -R app:app /app /data

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "secops_lab.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
