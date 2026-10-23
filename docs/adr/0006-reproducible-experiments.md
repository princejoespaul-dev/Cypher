# ADR 0006: Reproducible evaluation

**Status:** Accepted.

Experiment configuration, seeds, arm definitions, ground-truth hash and software/model provenance are stored with outputs. Recorded model responses should be replayed for exact reproductions; fresh model calls must be reported separately as variance. A report must not imply performance results until a benchmark has been executed.
