.PHONY: install lint test evals cdv fetch-fixtures

install:
	uv venv .venv
	. .venv/bin/activate && uv pip install -e ".[dev]"

lint:
	. .venv/bin/activate && ruff check . && mypy src/pentimento

test:
	. .venv/bin/activate && pytest -q

evals:
	. .venv/bin/activate && python evals/run_evals.py

cdv:
	. .venv/bin/activate && pentimento cdv $(SRC) --out $(OUT)

fetch-fixtures:
	./scripts/fetch_fixtures.sh
