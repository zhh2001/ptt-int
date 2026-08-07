.PHONY: all build test smoke clean

all: build

build:
	bash scripts/build.sh

test:
	python3 -m unittest discover -s tests -v

smoke: build
	bash scripts/run_smoke.sh

clean:
	rm -f p4src/ptt_int.json
	rm -rf results/raw/*
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
