.PHONY: build-analyzer run-a2 run-b run-ab

A2_INPUT ?= a2/input/zlib.in.jsonl
A2_OUTPUT ?= a2/out/samples.raw.jsonl
B_INPUT ?= $(shell python3 pipeline.py stats-path --raw-output $(A2_OUTPUT))
B_OUTPUT_DIR ?= b/b_output
MIN_SUPPORT ?= 3
B_WORKERS ?=
B_WORKERS_ARG = $(if $(B_WORKERS),--workers $(B_WORKERS),)

build-analyzer:
	python3 pipeline.py build-analyzer

run-a2:
	python3 pipeline.py a2 --input $(A2_INPUT) --output $(A2_OUTPUT)

run-b:
	python3 pipeline.py b --input $(B_INPUT) --output-dir $(B_OUTPUT_DIR) --min-support $(MIN_SUPPORT) $(B_WORKERS_ARG)

run-ab:
	python3 pipeline.py ab --a2-input $(A2_INPUT) --a2-output $(A2_OUTPUT) --b-output-dir $(B_OUTPUT_DIR) --min-support $(MIN_SUPPORT) $(B_WORKERS_ARG)
