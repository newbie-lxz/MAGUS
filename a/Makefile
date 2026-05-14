.PHONY: build-analyzer run-a run-llm clean-out

INPUT ?= input/zlib.in.jsonl
OUTPUT ?= out/samples.raw.jsonl

build-analyzer:
	make -C analyzer

run-a:
	python3 cmd/miner.py --input $(INPUT) --output $(OUTPUT)

run-llm:
	python3 cmd/llm_export.py --input $(OUTPUT) --projects $(INPUT)

clean-out:
	find out -mindepth 1 -not -name '.gitkeep' -exec rm -rf {} +
