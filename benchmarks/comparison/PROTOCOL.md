# Scanner comparison protocol (2026-11)

This file fixes the method before any timed run. It is committed and pushed
before the first timed run. Rustleaks code does not change between this
commit and the report. A change starts a new comparison.

## Questions

1. Startup: time and memory to scan an empty or tiny input.
2. Throughput: time, CPU and memory on real repositories and on a size series,
   in `dir` mode and in `git` mode.
3. Quality: precision and recall on labeled data whose labels no scanner
   produced, and agreement on each tool's own rule examples.
4. Scaling: time with 1, 4 and all threads, and on dense findings.

Results are reported per question and per workload family, never as one
blended score.

## Host

Apple M5 Ultra, 36 cores, 256 GB memory, macOS 27.2, one host only. No Linux
host is available. Results apply only to this host, these versions and these
inputs. Before each run: no builds, agents, profilers or other benchmarks;
Bazel servers stopped; load average and thermal state recorded by the harness.

## Tools

| ID | Version | Build | SHA-256 |
| --- | --- | --- | --- |
| rustleaks-0.1.0-alpha.9 | 0.1.0-alpha.9 | release archive | `e7967563da6a7e19901799ec0c5f366d4cab130fb1de90ba7252c1ecc521a1a9` |
| rustleaks-main | main at `a83521cf5908b766af04df2186587203d02cac44` | `bazelisk build --config=release-macos-aarch64` | `e481014cb803c07e2f69557fe9dc49b253f14f242afc29dc7a6ce3eb51954402` |
| gitleaks-8.30.1 | 8.30.1 | release archive (go-re2) | `ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f` |
| betterleaks-1.10.1 | 1.10.1 | release archive | `13ac5109fa85a590c7ba6e7f130311e0c60a2bf582c3aac073176c93b46621a8` |
| betterleaks-2.0.0-rc.8 | 2.0.0-rc.8 | release archive | `5253cd8409d5468c28c4f6b5aa88dd0d8dfcb6caab2faee7697fef66afb12d42` |
| kingfisher-2.19.1 | 2.19.1 | release archive | `831e2bafbb344644632490ada21c55e4843d8908ca794eb2bbe7b590ccb6bc2b` |

The harness checks every hash before and after each run.

## Workloads

- `public-repos`: 14 repositories pinned by tag and commit, fetched and
  verified with `cargo xtask compare-workloads verify`. Nine are the
  repositories in Kingfisher's own benchmark; reports show those and the other
  five as separate groups.
- `synthetic`: 71 generated workloads. The 19 earlier workloads are marked
  tuned, because Rustleaks was tuned on them, and are reported apart.
- `fixtures-matrix`: each tool's own rule examples (Gitleaks, Betterleaks
  2.0.0-rc.8, Kingfisher 2.19.1 and 1.113.0, Rustleaks packs), each run
  against every tool.
- `constructed-v1`: the labeled synthetic quality corpus.
- Held-out set: sealed on 2026-11-17 by an agent independent of Rustleaks
  tuning, inventory SHA-256
  `5aca16b8fd8f1b03c04680f07fba4251675214e66ad14dc98707c4705c1ec927`. The seal
  is checked before the run. It has not been scanned by any tool before this
  run.
- CredData: not included unless the maintainer allows running its download
  script. If included later, it is a separate, labeled addition.

## Runs

Each run is a separate `cargo xtask compare run` with its own private output
folder. Defaults: 3 warmups, then 30 measured runs for cells under 1 s, 10
for cells of 1 s or more, and 3 for cells of 5 minutes or more; one-hour
timeout per sample; fixed seed; random tool and workload order.

| Run | Workloads | Modes | Lanes | Tools | Notes |
| --- | --- | --- | --- | --- | --- |
| R1 | public-repos, all 14 | dir | defaults (warm) | all 6 | headline throughput |
| R2 | public-repos except linux and gitlab | git | defaults (warm) | all 6 | headline history |
| R3 | linux, gitlab | git | defaults (warm) | rustleaks-main, gitleaks, betterleaks-2.0.0-rc.8, kingfisher | 1 run, no warmup: single observations, labeled as such, because one history scan takes many minutes |
| R4 | synthetic, 70 of 71 (`empty-stdin` is a stdin workload the harness does not run) | per workload | defaults (warm) | all 6 | tuned workloads reported apart |
| R4c | tiny-positive, tiny-clean-file, tiny-clean-tree | dir | defaults (cold: fresh HOME) | all 6 | startup with empty tool caches |
| R5 | rails, django, keyword-dense-16mib, mixed-source-16mib | dir, git | threads (1, 4, all), features, shared-rules, rustleaks-2x2 | all 6 | settings lanes |
| R6 | held-out perf and git workloads | per workload | defaults, threads | all 6 | sealed inputs |
| R7 | constructed-v1 and fixtures-matrix | dir | defaults | all 6 | quality only: 1 run, no warmup; timings not reported |
| R7h | held-out quality | dir | defaults | all 6 | quality only: 1 run, no warmup; timings not reported |

Commands, with `TOOLS` the private tools manifest, `CACHE` the workload cache
on a case-sensitive volume, `HELD` the sealed held-out folder, `W` the
`benchmarks/comparison/workloads` folder and `Q` the
`benchmarks/comparison/quality` folder. Every run also passes
`--tools TOOLS --output <new private folder>`.

```sh
# R1
cargo xtask compare run --workloads W/public-repos.json --cache-root CACHE \
  --lanes defaults --cache warm --modes dir --target-config run
# R2: every repository except linux and gitlab
cargo xtask compare run --workloads W/public-repos.json --cache-root CACHE \
  --lanes defaults --cache warm --modes git --target-config run \
  --workload croc --workload flask --workload jq --workload select2 \
  --workload rails --workload django --workload ruby --workload lucene \
  --workload bootstrap --workload prometheus --workload mongo --workload typescript
# R3
cargo xtask compare run --workloads W/public-repos.json --cache-root CACHE \
  --lanes defaults --cache warm --modes git --target-config run \
  --workload linux --workload gitlab --warmups 0 --runs 1 \
  --tool rustleaks-main --tool gitleaks-8.30.1 \
  --tool betterleaks-2.0.0-rc.8 --tool kingfisher-2.19.1
# R4
cargo xtask compare run --workloads W/synthetic.json --cache-root CACHE \
  --lanes defaults --cache warm
# R4c
cargo xtask compare run --workloads W/synthetic.json --cache-root CACHE \
  --lanes defaults --cache cold --workload tiny-positive \
  --workload tiny-clean-file --workload tiny-clean-tree
# R5
cargo xtask compare run --workloads W/public-repos.json \
  --workloads W/synthetic.json --cache-root CACHE \
  --lanes threads,features,shared-rules,rustleaks-2x2 --cache warm \
  --workload rails --workload django --workload keyword-dense-16mib \
  --workload mixed-source-16mib
# R6
cargo xtask compare run --workloads HELD-manifest.json --cache-root HELD \
  --lanes defaults,threads --cache warm --workload heldout-perf-10m \
  --workload heldout-perf-100m --workload heldout-perf-500m --workload heldout-git
# R7
cargo xtask compare run --workloads Q/labeled.json \
  --workloads W/fixtures-matrix.json --cache-root CACHE --lanes defaults \
  --cache warm --modes dir --warmups 0 --runs 1
# R7h
cargo xtask compare run --workloads HELD-manifest.json --cache-root HELD \
  --lanes defaults --cache warm --workload heldout-quality --warmups 0 --runs 1
```

`HELD-manifest.json` maps the sealed set's own manifest to the workload
schema without changing any sealed file. Repositories carrying their own
configuration or ignore file at the scan root (gitlab carries
`.gitleaksignore`) run with `--target-config run`: Gitleaks, Rustleaks and
Betterleaks 1 load that file as a user scanning the repository would, and
the harness flags those cells.

## Analysis

- Timing: median, MAD, min and max per cell; bootstrap 95 percent intervals
  for ratios of medians for every pair of tools in the same cell; bimodal
  cells flagged; all raw samples kept.
- Throughput from `dir` cells only, as input bytes from the manifest divided by
  median wall time.
- Memory: peak RSS of the scanner, plus its Git child processes where
  measured.
- Quality: one-to-one maximum matching on path, commit and secret text, in
  both directions. In `git` mode, commit-agnostic matching is shown next to
  commit matching. Precision, recall and F1 are given by category and source.
  Scope differences (merges, unreachable commits, binaries) are reported as
  their own rows.
- Every failed, skipped, timed-out or flagged cell is listed with its reason.

## Disclosures

- Rule counts and sources per tool. Rustleaks packs and Kingfisher draw on
  rule sources derived from Betterleaks; Kingfisher takes 472 of its 503 rules
  from Betterleaks 2.0.0-rc.7.
- Every non-default flag per tool and lane, with the reason, as recorded by
  the harness.
- Scope differences: `.git` handling in `dir` mode, patches versus blobs in
  history, chunked versus whole-file reading, merge diffs.
- Inputs used during Rustleaks development: the 19 tuned synthetic
  workloads and the Rustleaks pack fixtures.
- The page cache is not purged between runs; cold cells use a fresh HOME only.
