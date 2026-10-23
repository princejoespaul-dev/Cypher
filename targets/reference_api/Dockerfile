FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.128.2 uvicorn==0.40.0 pydantic==2.13.5
COPY app.py ./app.py
RUN useradd --create-home --uid 10002 reference
USER 10002:10002
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
