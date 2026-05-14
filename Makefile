.PHONY: build-analyzer run-a run-llm run-b run-ab

A_INPUT ?= a/input/zlib.in.jsonl
A_OUTPUT ?= a/out/samples.raw.jsonl
LLM_OUTPUT ?=
B_INPUT ?= $(shell python3 pipeline.py stats-path --raw-output $(A_OUTPUT))
B_OUTPUT_DIR ?= b/b_output
MIN_SUPPORT ?= 3
LLM_OUTPUT_ARG = $(if $(LLM_OUTPUT),--output $(LLM_OUTPUT),)
AB_LLM_OUTPUT_ARG = $(if $(LLM_OUTPUT),--llm-output $(LLM_OUTPUT),)

build-analyzer:
	python3 pipeline.py build-analyzer

run-a:
	python3 pipeline.py a --input $(A_INPUT) --output $(A_OUTPUT)

run-llm:
	python3 pipeline.py llm --input $(A_OUTPUT) --projects $(A_INPUT) $(LLM_OUTPUT_ARG)

run-b:
	python3 pipeline.py b --input $(B_INPUT) --output-dir $(B_OUTPUT_DIR) --min-support $(MIN_SUPPORT)

run-ab:
	python3 pipeline.py ab --a-input $(A_INPUT) --a-output $(A_OUTPUT) $(AB_LLM_OUTPUT_ARG) --b-output-dir $(B_OUTPUT_DIR) --min-support $(MIN_SUPPORT)
