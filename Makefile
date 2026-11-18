.PHONY: all samples run eval correlate test demo clickhouse clean
all: samples run eval correlate
samples:   ; python3 scripts/gen_samples.py --n 2000
run:       ; python3 normalize.py
eval:      ; python3 eval/metrics.py
correlate: ; python3 eval/correlate.py
test:      ; python3 -m pytest -q tests
demo:      ; ./demo.sh
clickhouse:; python3 deploy/load_clickhouse.py
clean:     ; rm -f output/*.db output/*.ndjson output/*.json
