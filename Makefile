.PHONY: up down test lint typecheck imports openapi migrate clean reproduce

up:
	docker compose up --build -d postgres redis minio api

down:
	docker compose down

test:
	PYTHONPATH=src python -m pytest -q

lint:
	ruff check src tests migrations
	ruff format --check src tests migrations

typecheck:
	mypy src/cypher

imports:
	lint-imports

openapi:
	PYTHONPATH=src python scripts/export_openapi.py

migrate:
	alembic upgrade head

reproduce:
	PYTHONPATH=src python scripts/reproduce.py $(EXPERIMENT)

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist *.egg-info
