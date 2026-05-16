.PHONY: build-analyzer run-a2 clean-out

INPUT ?= input/zlib.in.jsonl
OUTPUT ?= out/samples.raw.jsonl

build-analyzer:
	make -C analyzer

run-a2:
	python3 cmd/miner.py --input $(INPUT) --output $(OUTPUT)

clean-out:
	find out -mindepth 1 -not -name '.gitkeep' -exec rm -rf {} +
