.PHONY: build-analyzer gen-srcs-compile-commands gen-input run-a run-llm run-b run-c run-ab run-abc

A_INPUT ?= a/input/zlib.in.jsonl
A_OUTPUT ?= a/out/samples.raw.jsonl
SRC_ROOT ?= srcs
COMPILE_COMMANDS ?= $(SRC_ROOT)/compile_commands.json
SRC_CC_OUTPUT ?= $(COMPILE_COMMANDS)
SRC_CC ?= clang
SRC_CXX ?= clang++
SRC_CC_SOURCE_GLOB ?=
SRC_CC_INCLUDE_DIR ?=
SRC_CC_FORCE ?=
GEN_INPUT_OUTPUT ?= a/input/srcs.in.jsonl
GEN_PROJECT_ID ?= srcs
GEN_LANGUAGE ?= c
GEN_FRAMEWORK ?= generic
GEN_ANALYZER_JOBS ?= 2
GEN_ANALYSIS_TIMEOUT ?= 900
GEN_CLANG ?= clang
GEN_CLANGXX ?= clang++
GEN_BC_DIR ?= bc
GEN_SOURCE_GLOB ?=
GEN_FORCE ?=
B_INPUT ?= $(shell python3 pipeline.py stats-path --raw-output $(A_OUTPUT))
B_OUTPUT_DIR ?= b/b_output
B_CANDIDATES ?= $(B_OUTPUT_DIR)/candidates.scored.jsonl
C_LLM_INPUT ?= $(shell python3 pipeline.py llm-path --raw-output $(A_OUTPUT))
C_OUTPUT ?= c/out/hypotheses.jsonl
C_MAX_SAMPLES ?=
MIN_SUPPORT ?= 3

build-analyzer:
	python3 pipeline.py build-analyzer

gen-srcs-compile-commands:
	python3 tools/gen_srcs_compile_commands.py --repo-path $(SRC_ROOT) --output $(SRC_CC_OUTPUT) --cc $(SRC_CC) --cxx $(SRC_CXX) $(foreach glob,$(SRC_CC_SOURCE_GLOB),--source-glob $(glob)) $(foreach dir,$(SRC_CC_INCLUDE_DIR),--include-dir $(dir)) $(if $(SRC_CC_FORCE),--force,)

gen-input:
	python3 pipeline.py gen-input --repo-path $(SRC_ROOT) --compile-commands $(COMPILE_COMMANDS) --output $(GEN_INPUT_OUTPUT) --project-id $(GEN_PROJECT_ID) --language $(GEN_LANGUAGE) --framework $(GEN_FRAMEWORK) --analyzer-jobs $(GEN_ANALYZER_JOBS) --analysis-timeout $(GEN_ANALYSIS_TIMEOUT) --clang $(GEN_CLANG) --clangxx $(GEN_CLANGXX) --bc-dir $(GEN_BC_DIR) $(foreach glob,$(GEN_SOURCE_GLOB),--source-glob $(glob)) $(if $(GEN_FORCE),--force,)

run-a:
	python3 pipeline.py a --input $(A_INPUT) --output $(A_OUTPUT)

run-llm:
	python3 pipeline.py llm --input $(A_OUTPUT) --projects $(A_INPUT) --output $(C_LLM_INPUT)

run-b:
	python3 pipeline.py b --input $(B_INPUT) --output-dir $(B_OUTPUT_DIR) --min-support $(MIN_SUPPORT)

run-c:
	python3 pipeline.py c --llm-input $(C_LLM_INPUT) --b-candidates $(B_CANDIDATES) --output $(C_OUTPUT) $(if $(C_MAX_SAMPLES),--max-samples $(C_MAX_SAMPLES),)

run-ab:
	python3 pipeline.py ab --a-input $(A_INPUT) --a-output $(A_OUTPUT) --b-output-dir $(B_OUTPUT_DIR) --min-support $(MIN_SUPPORT)

run-abc:
	python3 pipeline.py abc --a-input $(A_INPUT) --a-output $(A_OUTPUT) --b-output-dir $(B_OUTPUT_DIR) --c-output $(C_OUTPUT) --min-support $(MIN_SUPPORT) $(if $(C_MAX_SAMPLES),--c-max-samples $(C_MAX_SAMPLES),)
