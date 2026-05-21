# Juliet Report Evaluation

`evaluate_juliet_report.py` compares the MAGUS final report with Juliet ground truth and writes paper-ready evaluation artifacts.

Default inputs:

- report: `report/verification.report.jsonl`
- Juliet root: `srcs/juliet-api-misuse`
- output: `test/out/juliet_eval`

Typical run for a scoped Juliet experiment:

```bash
python3 test/evaluate_juliet_report.py \
  --report report/verification.report.jsonl \
  --scope-compile-commands srcs/compile_commands.cwe15.json \
  --stage-a-start 2026-05-20T10:00:00Z
```

To time and evaluate a fresh full pipeline run in one command:

```bash
python3 test/evaluate_juliet_report.py \
  --run-command "python3 pipeline.py abcd" \
  --scope-compile-commands srcs/compile_commands.cwe15.json
```

The elapsed time is measured from Stage A start to final report generation. The script can infer the report end time from `report/verification.report.md` `generated_at`; pass `--report-generated-at` or `--timing-json` when that file is not available.

Generated artifacts:

- `summary.md`: human-readable metrics and FP/FN previews
- `summary.json`: machine-readable metrics, counts, and timing
- `false_positives.csv`: reported findings that map to Juliet good paths or outside the selected truth scope
- `false_negatives.csv`: Juliet bad cases not covered by the final report
- `true_positives.csv`: matched Juliet bad cases
- `duplicate_true_positives.csv`: extra reports for already covered Juliet bad cases
- `all_findings.csv`: one classification row per final report row
- `truth_cases.csv`: inferred or loaded Juliet answer set

Use `--answer-file` to supply an explicit JSONL/JSON/CSV answer set with `key` or `file`, plus one of `is_vulnerable`, `vulnerable`, `expected`, `label`, `verdict`, or `answer`.
