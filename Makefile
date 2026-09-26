.PHONY: all build test integration check clean
all: build
build:
	bash scripts/build.sh
test:
	python3 -m unittest discover -s tests -p 'test_*.py' -v
integration: build
	python3 -m unittest discover -s tests -p 'bmv2_*.py' -v
check: test integration
clean:
	rm -rf build
