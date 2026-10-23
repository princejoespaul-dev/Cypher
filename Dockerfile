# Development image; for a security evaluation override this tag with a reviewed digest.
ARG PYTHON_BASE_IMAGE=python:3.13-slim
FROM ${PYTHON_BASE_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY dashboard ./dashboard
COPY migrations ./migrations
COPY alembic.ini ./
RUN python -m pip install --no-cache-dir .
RUN useradd --create-home --uid 10001 cypher && mkdir -p /var/lib/cypher/evidence && chown -R cypher:cypher /app /var/lib/cypher
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "cypher.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
