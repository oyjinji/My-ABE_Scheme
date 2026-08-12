# FX-ABF experiment suite

This directory contains all new filter microbenchmarks, Transform-scaling experiments, raw records, summaries, manifests, logs and figures. Algorithm code remains in `Code/fxdacp`; no existing benchmark result is read or overwritten.

## Compared backends

| Plot label | Unified retrieval adaptation |
|---|---|
| Linear Scan | Sequential token scan; a non-private no-index baseline |
| Exact Hash | Exact SHA-256 token key to compact PStore identifier |
| Bloom+Exact-PStore | Bloom membership prefilter plus exact retrieval map; Bloom alone does not retrieve a posting list |
| Attribute-BF (greedy) | 2018-style greedy multi-position XOR assignment adapted to `PStore id + check` |
| Original-ABF | `ABE-Scheme+.md` random sid, check string, encrypted PStore and full seed rebuild behavior |
| as-ACF/Cuckoo | Static fingerprint, three candidate bins, multi-slot/multi-table adapter with an 85% threshold |
| XOR-Retrieval | Three global hashes, hypergraph peeling and reverse XOR assignment, without fuse segmentation |
| FX-ABF | The formal `Code.fxdacp.fxabf.FXABF` core with the versioned segmented position profile |

Every backend consumes `token -> posting_list` and returns a hit with the authenticated list or a miss. They use the same generated tokens, lists, AES-GCM nonce/tag sizes, compact row encoding and trial seeds. Size results are canonical serialized/array/PStore byte counts, not `sys.getsizeof`. The filters have different native functions and security properties; the adapters make retrieval costs comparable but do not make their privacy models equivalent.

## Layout

- `configs/`: smoke, standard and full experiment grids;
- `filters/`: the uniform interface and eight required structures;
- `generators/`: deterministic tokens, posting lists and fixed-N/r policies;
- `runners/`: six focused runners plus the unified `run_all` entry point;
- `plots/`: matplotlib-only redraw tools;
- `results/<run_id>/`: manifest, append-only raw JSONL, summary CSV, plot data and PNG/PDF;
- `logs/<profile>/`: run progress; `logs/tests/` contains test reports.

The eleven experiments cover build success/retries/expansion, query breakdown, storage, the full filter comparison, segment layout timing, fixed `N=32,r=8` Transform scaling, empirical nonmember rejection and joint sensitivity. Zero observed false accepts are reported as an empirical observation, never as proof of zero probability. Python timing is described as locality-oriented segment-layout timing, not as measured hardware cache-hit rate.

See `EXPERIMENT_GUIDE.md` for copyable commands and field definitions.
