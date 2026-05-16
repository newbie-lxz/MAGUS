.PHONY: build-analyzer run-a run-b run-ab

A_INPUT ?= a/input/zlib.in.jsonl
A_OUTPUT ?= a/out/samples.raw.jsonl
B_INPUT ?= $(shell python3 pipeline.py stats-path --raw-output $(A_OUTPUT))
B_OUTPUT_DIR ?= b/b_output
MIN_SUPPORT ?= 3

build-analyzer:
	python3 pipeline.py build-analyzer

run-a:
	python3 pipeline.py a --input $(A_INPUT) --output $(A_OUTPUT)

run-b:
	python3 pipeline.py b --input $(B_INPUT) --output-dir $(B_OUTPUT_DIR) --min-support $(MIN_SUPPORT)

run-ab:
	python3 pipeline.py ab --a-input $(A_INPUT) --a-output $(A_OUTPUT) --b-output-dir $(B_OUTPUT_DIR) --min-support $(MIN_SUPPORT)
