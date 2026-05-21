.PHONY: build-analyzer run-a clean-out

INPUT ?= input/srcs.in.jsonl
OUTPUT ?= out/samples.raw.jsonl

build-analyzer:
	make -C analyzer

run-a:
	python3 cmd/miner.py --input $(INPUT) --output $(OUTPUT)

clean-out:
	find out -mindepth 1 -not -name '.gitkeep' -exec rm -rf {} +
