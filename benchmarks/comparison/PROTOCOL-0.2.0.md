# Scanner comparison protocol (0.2.0 candidate)

This file fixed the method of the 0.2.0 candidate comparison before its
first timed run. Rustleaks code did not change between this file and the
[results](results-0.2.0.md). The method follows the
[2026-11 protocol](PROTOCOL.md) except where this file says otherwise.

## Questions

1. Does the candidate show a time, memory or finding regression against
   the previous release, 0.1.0-alpha.12?
2. Startup, throughput, history, scaling and quality of the candidate next
   to the other scanners, asked as in the 2026-11 protocol.

## Host

Apple M5 Ultra, 36 cores, 256 GB memory, macOS 27.2.1, Git 2.56.1,
Python 3.9.6, one host only. Results apply only to this host, these
versions and these inputs. Before each run: no builds, agents, profilers or
other benchmarks; Bazel servers stopped; load average and thermal state
recorded by the harness.

## Tools

| ID | Version | Build | SHA-256 |
| --- | --- | --- | --- |
| rustleaks-0.1.0-alpha.12 | 0.1.0-alpha.12 | macOS arm64 release archive, `SHA256SUMS` checked | `cdd258d2d4a9ad42f3f2021dae463bf39fa95ee5ae8fa7e0cea5707c1bbee18a` |
| rustleaks-candidate-4a50422 | `main` at commit `4a50422b` | `bazelisk build --config=release-macos-aarch64` | `2a17da87a99132fb28556a230aad234042f0875dee08c70a24bd4ad5adbc27e8` |
| gitleaks-8.30.1 | 8.30.1 | release archive (go-re2) | `ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f` |
| betterleaks-1.10.1 | 1.10.1 | release archive | `13ac5109fa85a590c7ba6e7f130311e0c60a2bf582c3aac073176c93b46621a8` |
| betterleaks-2.0.0-rc.8 | 2.0.0-rc.8 | release archive | `5253cd8409d5468c28c4f6b5aa88dd0d8dfcb6caab2faee7697fef66afb12d42` |
| kingfisher-2.19.1 | 2.19.1 | release archive | `831e2bafbb344644632490ada21c55e4843d8908ca794eb2bbe7b590ccb6bc2b` |

The other scanners are the versions of the 2026-11 comparison, kept so the
two comparisons can be read together. The harness checks every hash before
and after each run. The baseline for ratios is 0.1.0-alpha.12.

## Workloads

- `public-repos`, `synthetic`, `fixtures-matrix` and `constructed-v1` as in
  the 2026-11 protocol, checked with
  `cargo xtask compare-workloads verify --set all` (91 workloads) before the
  run.
- Held-out set 1: sealed on 2026-11-17, inventory SHA-256
  `5aca16b8fd8f1b03c04680f07fba4251675214e66ad14dc98707c4705c1ec927`.
- Held-out set 2: a quality-only set sealed on 2026-11-19, inventory
  SHA-256
  `8098190cef82810a60171802216e962ad00b0180b56efe8abdf7c294238d7f5f`.
- Before the run, every file of both held-out sets was hashed and matched
  its sealed inventory. Earlier comparisons scanned both sets; no Rustleaks
  rule or code change was made in response to their held-out results.

## Runs

Quick settings: one warmup, then 3 measured runs per cell; one-hour timeout
per sample; an 8-hour budget per run; seed `20261123`; random tool and
workload order. Each run has its own private output folder.

| Run | Workloads | Modes | Lanes | Notes |
| --- | --- | --- | --- | --- |
| R7 | constructed-v1 and fixtures-matrix | dir | defaults | quality only: 1 run, no warmup |
| R7h | held-out set 1 quality | dir | defaults | quality only: 1 run, no warmup |
| R7h2 | held-out set 2 quality | dir | defaults | quality only: 1 run, no warmup |
| R1 | public-repos, all 14 | dir | defaults (warm) | throughput |
| R2 | public-repos except linux and gitlab | git | defaults (warm) | history |
| R4 | synthetic, 70 of 71 | per workload | defaults (warm) | tuned workloads reported apart |
| R4c | tiny-positive, tiny-clean-file, tiny-clean-tree | dir | defaults (warm and cold) | startup |
| R5 | rails, django, keyword-dense-16mib, mixed-source-16mib | dir, git | threads (1, 4, 12, all), features, shared-rules | settings lanes |
| R6 | held-out perf and git workloads | per workload | defaults, threads | sealed inputs |

The commands are those of the 2026-11 protocol with `--seed 20261123`,
`--baseline rustleaks-0.1.0-alpha.12`, `--warmups 1 --runs 3` on timed
runs, and R7h2 added:

```sh
# R7h2, with HELD2 the second sealed folder
cargo xtask compare run --workloads HELD2/manifest.json --cache-root HELD2 \
  --lanes defaults --cache warm --workload heldout-quality --warmups 0 --runs 1
```

## Changes from the 2026-11 protocol

- Six tools: the two Rustleaks builds are the previous release and the
  candidate.
- The `rustleaks-2x2` lane is left out. Both Rustleaks builds use every
  built-in rule and have no rule packs to turn on or off.
- `--runs 3` is passed, so the harness marks the runs as not protocol runs
  of its own default counts.
- Held-out set 2 is added.

## Analysis

As in the 2026-11 protocol. In addition, every cell where the candidate
reports a different number of findings than 0.1.0-alpha.12 is listed with
its cause. A candidate cell more than 10% slower or larger than
0.1.0-alpha.12, outside the bootstrap interval, is listed with its cause or
marked unexplained.
