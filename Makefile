.PHONY: test test-unit test-cov install-dev

install-dev:
	pip install -r requirements-dev.txt

test:
	python -m pytest tests/ -v

test-unit:
	python -m pytest tests/ -v -m unit

test-cov:
	python -m pytest tests/ --cov=modules --cov=web --cov-report=term-missing --cov-report=html
