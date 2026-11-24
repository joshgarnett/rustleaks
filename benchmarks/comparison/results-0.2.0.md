# Scanner comparison results (0.2.0 candidate)

These are the results of the runs fixed in [PROTOCOL-0.2.0.md](PROTOCOL-0.2.0.md),
made on 2026-11-23. They apply only to that host, those tool versions and
those inputs. Raw samples, reports and logs are private and are not in the
repository.

## How to read the tables

- Each cell is median wall time, median peak RSS and the finding count of the
  last measured run, from 1 warmup and 3 measured runs. Quality runs use one
  run and report no time.
- "Candidate" is the `rustleaks-candidate-4a50422` build named in the
  protocol. "Rustleaks 0.1.0-alpha.12" is the previous release.
- Ratios are candidate divided by 0.1.0-alpha.12, with bootstrap 95 percent
  intervals. A ratio below 1 means the candidate used less.
- Finding counts are not comparable as a measure of quality. Tools use
  different rules, and Kingfisher reports each distinct value once by
  default. Quality is in its own section, measured against labels that no
  scanner produced.
- Memory is the peak RSS of the largest single process. In `git` mode that
  can be a `git` child.
- "(varies)" marks a cell whose finding count was the same in every sample
  but whose set of findings was not.

## Deviations and failures

All 1,050 timed cells and 54 quality cells finished, with 3,150 measured
samples. No sample failed or timed out, and no cell was skipped. The harness
checked every tool hash before and after each run. It flagged 27 cells:

- The gitlab folder cells of both Rustleaks builds, Gitleaks and Betterleaks
  1.10.1 in R1. These tools load the `.gitleaksignore` at the gitlab root,
  as the protocol allows with `--target-config run`.
- 23 Kingfisher cells whose set of findings changed between samples: gitlab,
  mongo, rails and ruby in R1; django, lucene, mongo, rails and ruby in R2;
  and 14 thread and features cells on rails and django in R5. Kingfisher
  reports each distinct value once and picks one of its locations, which can
  change between runs.

## Candidate against 0.1.0-alpha.12

Over the 172 timed cells, the geometric mean of candidate divided by
0.1.0-alpha.12 is 0.90 for wall time, 0.85 for CPU time and 0.80 for peak
RSS. No cell has a ratio above 1.05 for wall time or peak RSS. Two cells use
more than 5% more CPU time, with wall time unchanged and less memory:

| Workload | Wall | CPU | Peak RSS |
| --- | --- | --- | --- |
| base64-uris-4mib | 1.03 [0.97, 1.03] | 1.13 [1.08, 1.14] | 0.91 [0.90, 0.91] |
| dense-generic-single-line-400k | 0.98 [0.94, 0.99] | 1.08 [1.05, 1.12] | 0.88 [0.86, 0.92] |

The protocol lists cells more than 10% slower or larger, which these are
not, so their cause was not investigated.

Ratios on the public repositories and the held-out performance inputs:

| Run | Workload | Mode | Wall | CPU | Peak RSS | Findings |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | bootstrap | dir | 0.89 [0.84, 0.90] | 0.70 [0.68, 0.72] | 0.67 [0.66, 0.67] | 0 |
| R1 | croc | dir | 0.83 [0.82, 0.85] | 0.74 [0.74, 0.76] | 0.67 [0.67, 0.69] | 5 |
| R1 | django | dir | 0.90 [0.87, 0.93] | 0.72 [0.70, 0.73] | 0.71 [0.70, 0.73] | 8 |
| R1 | flask | dir | 0.83 [0.82, 0.85] | 0.78 [0.76, 0.79] | 0.69 [0.69, 0.70] | 6 |
| R1 | gitlab | dir | 0.91 [0.89, 0.92] | 0.71 [0.71, 0.72] | 0.69 [0.67, 0.69] | 417 (alpha.12: 418) |
| R1 | jq | dir | 0.88 [0.85, 0.89] | 0.72 [0.71, 0.74] | 0.68 [0.66, 0.69] | 0 |
| R1 | linux | dir | 0.90 [0.90, 0.92] | 0.63 [0.62, 0.63] | 0.72 [0.71, 0.74] | 242 |
| R1 | lucene | dir | 0.91 [0.79, 0.94] | 0.72 [0.69, 0.72] | 0.73 [0.71, 0.74] | 21 |
| R1 | mongo | dir | 0.90 [0.90, 0.91] | 0.67 [0.67, 0.68] | 0.70 [0.70, 0.72] | 1130 |
| R1 | prometheus | dir | 0.86 [0.85, 0.92] | 0.69 [0.68, 0.72] | 0.71 [0.68, 0.74] | 357 |
| R1 | rails | dir | 0.93 [0.89, 0.95] | 0.73 [0.72, 0.74] | 0.75 [0.74, 0.77] | 36 |
| R1 | ruby | dir | 0.92 [0.86, 0.95] | 0.76 [0.75, 0.78] | 0.76 [0.75, 0.77] | 68 |
| R1 | select2 | dir | 0.89 [0.85, 0.92] | 0.86 [0.83, 0.87] | 0.78 [0.76, 0.79] | 0 |
| R1 | typescript | dir | 0.95 [0.93, 0.99] | 0.80 [0.79, 0.81] | 0.72 [0.69, 0.75] | 48 |
| R2 | bootstrap | git | 0.99 [0.98, 0.99] | 0.85 [0.85, 0.85] | 0.88 [0.86, 0.90] | 7 |
| R2 | croc | git | 0.92 [0.89, 1.03] | 0.91 [0.89, 0.96] | 0.76 [0.74, 0.77] | 21 |
| R2 | django | git | 0.98 [0.97, 0.99] | 0.94 [0.93, 0.95] | 0.77 [0.76, 0.79] | 18 |
| R2 | flask | git | 0.94 [0.92, 0.97] | 0.93 [0.92, 0.93] | 0.65 [0.64, 0.65] | 12 |
| R2 | jq | git | 0.96 [0.95, 0.97] | 0.92 [0.92, 0.94] | 0.72 [0.70, 0.72] | 0 |
| R2 | lucene | git | 0.99 [0.98, 1.00] | 0.95 [0.94, 0.95] | 0.92 [0.91, 0.96] | 119 |
| R2 | mongo | git | 0.99 [0.98, 0.99] | 0.90 [0.90, 0.91] | 0.98 [0.94, 1.00] | 3381 |
| R2 | prometheus | git | 0.99 [0.99, 1.01] | 0.96 [0.95, 0.97] | 0.89 [0.89, 0.90] | 1183 |
| R2 | rails | git | 0.99 [0.99, 1.00] | 0.93 [0.93, 0.94] | 0.79 [0.78, 0.84] | 122 |
| R2 | ruby | git | 0.99 [0.99, 1.01] | 0.96 [0.95, 0.96] | 1.04 [0.93, 1.07] | 154 |
| R2 | select2 | git | 0.98 [0.97, 0.98] | 0.98 [0.97, 0.98] | 0.87 [0.84, 0.88] | 0 |
| R2 | typescript | git | 0.99 [0.99, 1.00] | 0.93 [0.92, 0.93] | 0.87 [0.85, 0.89] | 432 |
| R6 | heldout-git | git | 0.95 [0.92, 0.98] | 0.94 [0.93, 0.96] | 0.79 [0.78, 0.81] | 101 (alpha.12: 102) |
| R6 | heldout-perf-100m | dir | 0.90 [0.87, 0.94] | 0.79 [0.79, 0.81] | 0.76 [0.76, 0.78] | 89 (alpha.12: 90) |
| R6 | heldout-perf-10m | dir | 0.92 [0.87, 0.99] | 0.83 [0.81, 0.84] | 0.73 [0.72, 0.74] | 11 |
| R6 | heldout-perf-500m | dir | 0.91 [0.90, 0.95] | 0.66 [0.66, 0.67] | 0.77 [0.75, 0.79] | 272 (alpha.12: 273) |

### Findings that changed

The finding count changed in 18 timed cells: gitlab in R1, the five
`dense-planetscale-pairs` workloads in R4, and the held-out `git`, 100 MB
and 500 MB inputs in R6 (default and thread cells). It also changed in five
quality cells: `fixtures-gitleaks` (6,925 to 6,898), `fixtures-betterleaks`
(1,348 to 1,336), `fixtures-kingfisher-v1` (1,261 to 1,249),
`fixtures-rustleaks` (1,881 to 1,876) and held-out set 1 (2,673 to 2,660).
In every quality report, the candidate and 0.1.0-alpha.12 have the same true
positives and the same missed values.

Each finding that 0.1.0-alpha.12 reports and the candidate does not was
checked: the candidate reports the same secret, at the same file, commit
and line, under the other rule of a pair listed in
`rustleaks-providers-v1`. This is the change that reports one finding when
two built-in rules match a secret (see the [changelog](../../CHANGELOG.md)).
No secret was lost, and the candidate reports no finding that
0.1.0-alpha.12 does not.

| Dropped rule | Kept rule | Where |
| --- | --- | --- |
| `rustleaks.alibaba-access-key-id-boundary` | `alibaba-access-key-id` | gitlab, held-out sets, Gitleaks, Betterleaks and Kingfisher examples |
| `rustleaks.association.planetscale-api-token` | `planetscale-api-token` | `dense-planetscale-pairs`, Betterleaks examples |
| `rustleaks.grafana-api-key-base64` | `grafana-api-key` | Gitleaks, Kingfisher, Betterleaks and Rustleaks examples |
| `stripe-access-token` | `rustleaks.workos-production-api-key`, `rustleaks.highnote-secret-live-key` | Betterleaks and Kingfisher examples |
| `jwt` | `rustleaks.temporal-cloud-api-key`, `rustleaks.monday-api-token` | Betterleaks, Kingfisher and Rustleaks examples |
| `rustleaks.xai-api-key-80` | `rustleaks.xai-api-key-delimiter` | Kingfisher examples |
| `rustleaks.stripe-access-token-delimiter` | `rustleaks.clerk-secret-key-delimiter` | Rustleaks examples |
| `rustleaks.gitlab-incoming-mail-address-token` | `gitlab-incoming-mail-token` | Betterleaks examples |
| `rustleaks.association.artifactory-api-key`, `rustleaks.association.artifactory-reference-token` | `artifactory-*` and `jfrog-*` | Betterleaks examples |

## Startup (R4c)

Warm cells:

| Workload | Candidate | Rustleaks 0.1.0-alpha.12 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| tiny-clean-file | 40 ms, 30 MiB, 0 | 45 ms, 36 MiB, 0 | 172 ms, 69 MiB, 0 | 24 ms, 36 MiB, 0 | 35 ms, 39 MiB, 0 | 202 ms, 129 MiB, 0 |
| tiny-clean-tree | 39 ms, 30 MiB, 0 | 46 ms, 38 MiB, 0 | 174 ms, 72 MiB, 0 | 24 ms, 38 MiB, 0 | 36 ms, 40 MiB, 0 | 200 ms, 130 MiB, 0 |
| tiny-positive | 40 ms, 30 MiB, 1 | 45 ms, 36 MiB, 1 | 174 ms, 67 MiB, 1 | 24 ms, 36 MiB, 1 | 36 ms, 38 MiB, 1 | 215 ms, 141 MiB, 1 |

Cold cells (fresh `HOME`, empty tool caches):

| Workload | Candidate | Rustleaks 0.1.0-alpha.12 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| tiny-clean-file | 39 ms, 30 MiB, 0 | 45 ms, 36 MiB, 0 | 173 ms, 66 MiB, 0 | 157 ms, 51 MiB, 0 | 170 ms, 53 MiB, 0 | 2.27 s, 190 MiB, 0 |
| tiny-clean-tree | 40 ms, 31 MiB, 0 | 46 ms, 38 MiB, 0 | 174 ms, 73 MiB, 0 | 153 ms, 52 MiB, 0 | 164 ms, 54 MiB, 0 | 2.27 s, 191 MiB, 0 |
| tiny-positive | 40 ms, 30 MiB, 1 | 46 ms, 36 MiB, 1 | 173 ms, 66 MiB, 1 | 157 ms, 51 MiB, 1 | 170 ms, 53 MiB, 1 | 2.27 s, 208 MiB, 1 |

The candidate starts in 39 to 40 ms with 30 to 31 MiB, against 45 to 46 ms
and 36 to 38 MiB for 0.1.0-alpha.12. Betterleaks 1.10.1 and 2.0.0-rc.8 start
faster with a warm cache.

## Folder scans of public repositories (R1)

| Workload | Candidate | Rustleaks 0.1.0-alpha.12 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| bootstrap | 60 ms, 54 MiB, 0 | 68 ms, 80 MiB, 0 | 769 ms, 118 MiB, 0 | 137 ms, 97 MiB, 0 | 174 ms, 108 MiB, 0 | 227 ms, 142 MiB, 0 |
| croc | 52 ms, 59 MiB, 5 | 62 ms, 88 MiB, 5 | 296 ms, 100 MiB, 5 | 221 ms, 97 MiB, 65 | 272 ms, 100 MiB, 65 | 220 ms, 140 MiB, 0 |
| django | 195 ms, 108 MiB, 8 | 217 ms, 152 MiB, 8 | 2.12 s, 122 MiB, 8 | 550 ms, 147 MiB, 425 | 683 ms, 154 MiB, 427 | 512 ms, 161 MiB, 2 |
| flask | 47 ms, 50 MiB, 6 | 56 ms, 73 MiB, 6 | 218 ms, 87 MiB, 6 | 129 ms, 82 MiB, 6 | 164 ms, 87 MiB, 6 | 209 ms, 137 MiB, 0 |
| gitlab | 2.44 s, 319 MiB, 417 | 2.69 s, 466 MiB, 418 | 54.2 s, 169 MiB, 404 | 8.75 s, 194 MiB, 1226 | 5.58 s, 209 MiB, 1318 | 7.09 s, 2391 MiB, 110 (varies) |
| jq | 51 ms, 47 MiB, 0 | 58 ms, 68 MiB, 0 | 253 ms, 101 MiB, 0 | 187 ms, 87 MiB, 0 | 186 ms, 95 MiB, 0 | 252 ms, 161 MiB, 0 |
| linux | 2.37 s, 192 MiB, 242 | 2.62 s, 266 MiB, 242 | 182 s, 156 MiB, 242 | 2.66 s, 181 MiB, 78 | 2.75 s, 187 MiB, 86 | 3.16 s, 393 MiB, 6 |
| lucene | 282 ms, 109 MiB, 21 | 310 ms, 149 MiB, 21 | 3.75 s, 125 MiB, 21 | 896 ms, 158 MiB, 20 | 652 ms, 176 MiB, 20 | 4.61 s, 205 MiB, 0 |
| mongo | 1.25 s, 204 MiB, 1130 | 1.39 s, 291 MiB, 1130 | 58.2 s, 154 MiB, 1059 | 1.77 s, 178 MiB, 517 | 1.93 s, 197 MiB, 1326 | 2.04 s, 348 MiB, 229 (varies) |
| prometheus | 90 ms, 100 MiB, 357 | 105 ms, 139 MiB, 357 | 1.42 s, 119 MiB, 20 | 442 ms, 128 MiB, 376 | 380 ms, 136 MiB, 377 | 266 ms, 256 MiB, 24 |
| rails | 138 ms, 110 MiB, 36 | 149 ms, 147 MiB, 36 | 1.63 s, 121 MiB, 25 | 469 ms, 132 MiB, 134 | 561 ms, 142 MiB, 151 | 364 ms, 161 MiB, 7 (varies) |
| ruby | 248 ms, 120 MiB, 68 | 270 ms, 158 MiB, 68 | 4.53 s, 130 MiB, 69 | 572 ms, 145 MiB, 141 | 599 ms, 152 MiB, 144 | 554 ms, 272 MiB, 49 (varies) |
| select2 | 55 ms, 49 MiB, 0 | 62 ms, 63 MiB, 0 | 269 ms, 100 MiB, 0 | 117 ms, 90 MiB, 0 | 159 ms, 97 MiB, 0 | 223 ms, 138 MiB, 0 |
| typescript | 2.14 s, 132 MiB, 48 | 2.27 s, 184 MiB, 48 | 33.7 s, 150 MiB, 48 | 2.11 s, 155 MiB, 2 | 2.26 s, 174 MiB, 9 | 4.34 s, 197 MiB, 0 |

The candidate is the fastest on 13 of 14 repositories. On typescript,
Betterleaks 1.10.1 is 2% faster. The candidate uses the
least memory of the six tools on 11 repositories; on gitlab, mongo and
linux, Gitleaks and both Betterleaks versions use less.

## History scans of public repositories (R2)

| Workload | Candidate | Rustleaks 0.1.0-alpha.12 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| bootstrap | 3.59 s, 343 MiB, 7 | 3.62 s, 388 MiB, 7 | 112 s, 547 MiB, 7 | 10.9 s, 468 MiB, 7 | 4.33 s, 1238 MiB, 9 | 1.20 s, 951 MiB, 0 |
| croc | 448 ms, 96 MiB, 21 | 486 ms, 126 MiB, 21 | 927 ms, 101 MiB, 21 | 765 ms, 110 MiB, 93 | 364 ms, 265 MiB, 93 | 334 ms, 213 MiB, 0 |
| django | 2.74 s, 173 MiB, 18 | 2.79 s, 223 MiB, 18 | 12.7 s, 484 MiB, 18 | 8.90 s, 482 MiB, 1088 | 2.66 s, 1141 MiB, 1093 | 1.95 s, 970 MiB, 2 (varies) |
| flask | 182 ms, 72 MiB, 12 | 193 ms, 110 MiB, 12 | 582 ms, 109 MiB, 12 | 433 ms, 108 MiB, 29 | 318 ms, 355 MiB, 29 | 370 ms, 218 MiB, 0 |
| jq | 187 ms, 67 MiB, 0 | 194 ms, 94 MiB, 0 | 631 ms, 110 MiB, 0 | 363 ms, 92 MiB, 0 | 255 ms, 296 MiB, 0 | 406 ms, 218 MiB, 0 |
| lucene | 4.05 s, 403 MiB, 119 | 4.09 s, 436 MiB, 119 | 56.5 s, 863 MiB, 120 | 16.8 s, 764 MiB, 204 | 4.80 s, 1379 MiB, 221 | 4.32 s, 1411 MiB, 8 (varies) |
| mongo | 16.7 s, 1103 MiB, 3381 | 16.9 s, 1130 MiB, 3381 | 197 s, 1963 MiB, 3210 | 62.2 s, 1755 MiB, 1292 | 19.0 s, 2224 MiB, 3909 | 11.7 s, 2837 MiB, 720 (varies) |
| prometheus | 1.90 s, 345 MiB, 1183 | 1.91 s, 387 MiB, 1183 | 7.13 s, 672 MiB, 34 | 6.49 s, 649 MiB, 1229 | 2.59 s, 1311 MiB, 1232 | 1.08 s, 1202 MiB, 28 |
| rails | 3.33 s, 265 MiB, 122 | 3.36 s, 337 MiB, 122 | 11.4 s, 629 MiB, 95 | 10.1 s, 572 MiB, 456 | 3.23 s, 1362 MiB, 576 | 3.79 s, 1298 MiB, 14 (varies) |
| ruby | 6.01 s, 282 MiB, 154 | 6.07 s, 272 MiB, 154 | 24.9 s, 977 MiB, 155 | 23.3 s, 832 MiB, 426 | 6.01 s, 2319 MiB, 441 | 8.40 s, 1591 MiB, 92 (varies) |
| select2 | 282 ms, 117 MiB, 0 | 288 ms, 135 MiB, 0 | 2.71 s, 168 MiB, 0 | 629 ms, 136 MiB, 0 | 333 ms, 550 MiB, 0 | 543 ms, 219 MiB, 0 |
| typescript | 25.5 s, 881 MiB, 432 | 25.7 s, 1013 MiB, 432 | 182 s, 2725 MiB, 432 | 76.5 s, 2501 MiB, 25 | 24.4 s, 3486 MiB, 80 | 44.9 s, 3686 MiB, 0 |

Fastest tool per repository: Kingfisher on 5 (bootstrap, croc, django,
mongo, prometheus), the candidate on 4 (flask, jq, lucene, select2) and
Betterleaks 2.0.0-rc.8 on 3 (rails, ruby, typescript; on ruby the two
medians differ by about 0.1 ms). The candidate has the lowest peak RSS
on 11 of 12 repositories. On ruby 0.1.0-alpha.12 is lower; there the peak
comes from a `git` child, and the candidate's scanner process alone uses
206 MiB against 252 MiB.

Kingfisher scans blobs, while Gitleaks, Betterleaks and Rustleaks scan each
commit's patch (see the scope differences in the
[2026-11 protocol](PROTOCOL.md#disclosures)).

## Synthetic workloads (R4)

Geometric mean of each tool's median wall time and peak RSS divided by the
candidate, over the workloads in each group:

| Group | Workloads | Candidate | Rustleaks 0.1.0-alpha.12 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| Not tuned | 52 | time 1.00x, memory 1.00x | time 1.12x, memory 1.24x | time 6.87x, memory 2.00x | time 4.04x, memory 3.56x | time 4.20x, memory 1.91x | time 4.73x, memory 3.92x |
| Tuned on by Rustleaks | 18 | time 1.00x, memory 1.00x | time 1.13x, memory 1.23x | time 3.96x, memory 2.39x | time 1.03x, memory 1.59x | time 1.17x, memory 1.64x | time 4.52x, memory 4.62x |

Workloads where another tool was more than 10% faster than the candidate:

| Workload | Group | Faster tool | Its time | Candidate |
| --- | --- | --- | --- | --- |
| binary-mix-1mib | not tuned | Betterleaks 1.10.1 | 40 ms | 46 ms |
| entropy-negatives-1024mib | not tuned | Kingfisher 2.19.1 | 402 ms | 966 ms |
| keyword-dense-1024mib | not tuned | Kingfisher 2.19.1 | 610 ms | 1.80 s |
| minified-1024mib | not tuned | Betterleaks 2.0.0-rc.8 | 709 ms | 1.05 s |
| files-100000 | tuned | Betterleaks 2.0.0-rc.8 | 996 ms | 1.26 s |
| git-20000 | tuned | Betterleaks 2.0.0-rc.8 | 186 ms | 241 ms |
| git-current-tree-control | tuned | Betterleaks 1.10.1 | 26 ms | 42 ms |
| git-staged-control | tuned | Betterleaks 2.0.0-rc.8 | 36 ms | 47 ms |
| heldout-mixed-8mib | tuned | Betterleaks 1.10.1 | 47 ms | 58 ms |
| json-4mib | tuned | Betterleaks 1.10.1 | 42 ms | 47 ms |
| json-768-files | tuned | Betterleaks 1.10.1 | 40 ms | 51 ms |
| mixed-clean-4mib | tuned | Betterleaks 1.10.1 | 36 ms | 49 ms |
| multilanguage-256kib | tuned | Betterleaks 1.10.1 | 29 ms | 43 ms |
| tiny-clean-file | tuned | Betterleaks 1.10.1 | 27 ms | 44 ms |
| tiny-clean-tree | tuned | Betterleaks 1.10.1 | 27 ms | 43 ms |
| tiny-positive | tuned | Betterleaks 1.10.1 | 43 ms | 55 ms |

Most of these take under 60 ms, where the candidate's startup of about
40 ms is most of the time.

## Thread scaling (R5)

Each tool gets the same thread count through its own setting, as recorded
by the harness. The mechanisms differ: Gitleaks keeps 40 goroutines,
Betterleaks 2 starts 4 workers per `GOMAXPROCS`, and Rustleaks takes
`--jobs`. Median wall time:

django, `git` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Candidate | 8.36 s | 3.50 s | 2.74 s | 2.51 s |
| Rustleaks 0.1.0-alpha.12 | 8.84 s | 3.56 s | 2.79 s | 2.55 s |
| Gitleaks 8.30.1 | 11.2 s | 9.01 s | 10.8 s | 12.7 s |
| Betterleaks 1.10.1 | 9.10 s | 8.77 s | 8.88 s | 8.93 s |
| Betterleaks 2.0.0-rc.8 | 10.8 s | 3.26 s | 2.57 s | 2.71 s |
| Kingfisher 2.19.1 | 14.9 s | 4.96 s | 2.66 s | 1.95 s |

rails, `git` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Candidate | 8.97 s | 4.46 s | 3.33 s | 3.31 s |
| Rustleaks 0.1.0-alpha.12 | 9.45 s | 4.51 s | 3.36 s | 3.35 s |
| Gitleaks 8.30.1 | 10.7 s | 9.16 s | 9.61 s | 11.5 s |
| Betterleaks 1.10.1 | 10.7 s | 10.1 s | 10.1 s | 10.2 s |
| Betterleaks 2.0.0-rc.8 | 10.0 s | 3.26 s | 3.13 s | 3.21 s |
| Kingfisher 2.19.1 | 19.9 s | 7.58 s | 4.66 s | 3.83 s |

django, `dir` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Candidate | 517 ms | 226 ms | 195 ms | 192 ms |
| Rustleaks 0.1.0-alpha.12 | 785 ms | 299 ms | 214 ms | 216 ms |
| Gitleaks 8.30.1 | 1.75 s | 772 ms | 1.60 s | 2.11 s |
| Betterleaks 1.10.1 | 1.13 s | 371 ms | 480 ms | 614 ms |
| Betterleaks 2.0.0-rc.8 | 892 ms | 364 ms | 581 ms | 734 ms |
| Kingfisher 2.19.1 | 731 ms | 547 ms | 491 ms | 509 ms |

keyword-dense-16mib, `dir` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Candidate | 307 ms | 122 ms | 81 ms | 77 ms |
| Rustleaks 0.1.0-alpha.12 | 347 ms | 139 ms | 89 ms | 88 ms |
| Gitleaks 8.30.1 | 866 ms | 566 ms | 791 ms | 1.11 s |
| Betterleaks 1.10.1 | 1.08 s | 444 ms | 718 ms | 1.30 s |
| Betterleaks 2.0.0-rc.8 | 1.11 s | 445 ms | 676 ms | 1.19 s |
| Kingfisher 2.19.1 | 308 ms | 241 ms | 228 ms | 231 ms |

mixed-source-16mib, `dir` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Candidate | 170 ms | 79 ms | 61 ms | 60 ms |
| Rustleaks 0.1.0-alpha.12 | 205 ms | 93 ms | 71 ms | 71 ms |
| Gitleaks 8.30.1 | 565 ms | 324 ms | 411 ms | 484 ms |
| Betterleaks 1.10.1 | 473 ms | 211 ms | 311 ms | 358 ms |
| Betterleaks 2.0.0-rc.8 | 454 ms | 222 ms | 307 ms | 359 ms |
| Kingfisher 2.19.1 | 298 ms | 243 ms | 239 ms | 244 ms |

rails, `dir` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Candidate | 348 ms | 161 ms | 140 ms | 133 ms |
| Rustleaks 0.1.0-alpha.12 | 519 ms | 205 ms | 151 ms | 150 ms |
| Gitleaks 8.30.1 | 1.28 s | 615 ms | 1.26 s | 1.65 s |
| Betterleaks 1.10.1 | 755 ms | 260 ms | 460 ms | 469 ms |
| Betterleaks 2.0.0-rc.8 | 646 ms | 289 ms | 504 ms | 520 ms |
| Kingfisher 2.19.1 | 535 ms | 397 ms | 363 ms | 362 ms |

In the features lane (decode and archive depths), the candidate's wall time
is 0.74 to 0.99 times and its peak RSS 0.77 to 0.90 times that of
0.1.0-alpha.12 over 18 cells. In the shared-rules lane, both builds load the
same small rule set and the candidate is within 5% of 0.1.0-alpha.12 on wall
time and peak RSS in all 12 cells.

## Held-out set (R6)

Sealed inputs that no Rustleaks change was tuned on. Default cells:

| Workload | Candidate | Rustleaks 0.1.0-alpha.12 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| heldout-git | 128 ms, 81 MiB, 101 | 135 ms, 102 MiB, 102 | 444 ms, 96 MiB, 102 | 434 ms, 110 MiB, 101 | 429 ms, 222 MiB, 112 | 327 ms, 195 MiB, 66 |
| heldout-perf-100m | 136 ms, 70 MiB, 89 | 151 ms, 92 MiB, 90 | 2.72 s, 117 MiB, 87 | 964 ms, 135 MiB, 82 | 957 ms, 165 MiB, 89 | 591 ms, 272 MiB, 62 |
| heldout-perf-10m | 67 ms, 44 MiB, 11 | 74 ms, 60 MiB, 11 | 542 ms, 106 MiB, 11 | 209 ms, 115 MiB, 11 | 262 ms, 118 MiB, 12 | 248 ms, 182 MiB, 8 |
| heldout-perf-500m | 449 ms, 99 MiB, 272 | 491 ms, 128 MiB, 273 | 10.3 s, 121 MiB, 268 | 1.86 s, 142 MiB, 273 | 1.86 s, 180 MiB, 289 | 672 ms, 494 MiB, 203 |

The candidate is the fastest and uses the least memory on all four. In the
thread cells (1, 4 and 36 threads) its wall time is 0.62 to 0.99 times that
of 0.1.0-alpha.12.

## Quality (R7, R7h and R7h2)

"FP on negatives" is findings on values labeled as not secret; "Unlabeled"
is findings on text with no label. Precision is the harness's strict
precision: true positives divided by true positives plus findings on
negatives, unlabeled findings and second findings on a value already
matched or reported more than once.

| Workload | Tool | Findings | TP | FN | FP on negatives | Unlabeled | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| constructed-v1 | Candidate | 1046 | 964 | 135 | 13 | 0 | 0.922 | 0.877 | 0.899 |
| constructed-v1 | Rustleaks 0.1.0-alpha.12 | 1046 | 964 | 135 | 13 | 0 | 0.922 | 0.877 | 0.899 |
| constructed-v1 | Gitleaks 8.30.1 | 1059 | 871 | 228 | 114 | 0 | 0.822 | 0.793 | 0.807 |
| constructed-v1 | Betterleaks 1.10.1 | 1149 | 940 | 159 | 126 | 0 | 0.818 | 0.855 | 0.836 |
| constructed-v1 | Betterleaks 2.0.0-rc.8 | 1193 | 972 | 127 | 138 | 0 | 0.815 | 0.884 | 0.848 |
| constructed-v1 | Kingfisher 2.19.1 | 711 | 669 | 430 | 3 | 0 | 0.941 | 0.609 | 0.739 |
| fixtures-betterleaks | Candidate | 1336 | 1024 | 78 | 165 | 102 | 0.766 | 0.929 | 0.840 |
| fixtures-betterleaks | Rustleaks 0.1.0-alpha.12 | 1348 | 1024 | 78 | 167 | 103 | 0.760 | 0.929 | 0.836 |
| fixtures-betterleaks | Gitleaks 8.30.1 | 1221 | 926 | 176 | 162 | 101 | 0.758 | 0.840 | 0.797 |
| fixtures-betterleaks | Betterleaks 1.10.1 | 1350 | 1074 | 28 | 143 | 95 | 0.796 | 0.975 | 0.876 |
| fixtures-betterleaks | Betterleaks 2.0.0-rc.8 | 1379 | 1102 | 0 | 156 | 95 | 0.799 | 1.000 | 0.888 |
| fixtures-betterleaks | Kingfisher 2.19.1 | 875 | 780 | 322 | 20 | 59 | 0.891 | 0.708 | 0.789 |
| fixtures-gitleaks | Candidate | 6898 | 6393 | 0 | 30 | 0 | 0.927 | 1.000 | 0.962 |
| fixtures-gitleaks | Rustleaks 0.1.0-alpha.12 | 6925 | 6393 | 0 | 30 | 0 | 0.923 | 1.000 | 0.960 |
| fixtures-gitleaks | Gitleaks 8.30.1 | 6895 | 6393 | 0 | 30 | 0 | 0.927 | 1.000 | 0.962 |
| fixtures-gitleaks | Betterleaks 1.10.1 | 6601 | 6113 | 280 | 30 | 0 | 0.926 | 0.956 | 0.941 |
| fixtures-gitleaks | Betterleaks 2.0.0-rc.8 | 6681 | 6269 | 124 | 32 | 0 | 0.938 | 0.981 | 0.959 |
| fixtures-gitleaks | Kingfisher 2.19.1 | 553 | 517 | 5876 | 7 | 0 | 0.935 | 0.081 | 0.149 |
| fixtures-kingfisher | Candidate | 21 | 12 | 0 | 9 | 0 | 0.571 | 1.000 | 0.727 |
| fixtures-kingfisher | Rustleaks 0.1.0-alpha.12 | 21 | 12 | 0 | 9 | 0 | 0.571 | 1.000 | 0.727 |
| fixtures-kingfisher | Gitleaks 8.30.1 | 10 | 1 | 11 | 9 | 0 | 0.100 | 0.083 | 0.091 |
| fixtures-kingfisher | Betterleaks 1.10.1 | 17 | 7 | 5 | 9 | 0 | 0.412 | 0.583 | 0.483 |
| fixtures-kingfisher | Betterleaks 2.0.0-rc.8 | 17 | 7 | 5 | 9 | 0 | 0.412 | 0.583 | 0.483 |
| fixtures-kingfisher | Kingfisher 2.19.1 | 12 | 12 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| fixtures-kingfisher-v1 | Candidate | 1249 | 1208 | 930 | 8 | 0 | 0.967 | 0.565 | 0.713 |
| fixtures-kingfisher-v1 | Rustleaks 0.1.0-alpha.12 | 1261 | 1208 | 930 | 8 | 0 | 0.958 | 0.565 | 0.711 |
| fixtures-kingfisher-v1 | Gitleaks 8.30.1 | 1133 | 1098 | 1040 | 8 | 0 | 0.969 | 0.514 | 0.671 |
| fixtures-kingfisher-v1 | Betterleaks 1.10.1 | 1237 | 1195 | 943 | 8 | 0 | 0.966 | 0.559 | 0.708 |
| fixtures-kingfisher-v1 | Betterleaks 2.0.0-rc.8 | 1299 | 1250 | 888 | 8 | 0 | 0.962 | 0.585 | 0.727 |
| fixtures-kingfisher-v1 | Kingfisher 2.19.1 | 510 | 497 | 1641 | 2 | 0 | 0.975 | 0.232 | 0.375 |
| fixtures-rustleaks | Candidate | 1876 | 1521 | 20 | 186 | 87 | 0.811 | 0.987 | 0.890 |
| fixtures-rustleaks | Rustleaks 0.1.0-alpha.12 | 1881 | 1521 | 20 | 186 | 87 | 0.809 | 0.987 | 0.889 |
| fixtures-rustleaks | Gitleaks 8.30.1 | 382 | 116 | 1425 | 178 | 60 | 0.304 | 0.075 | 0.121 |
| fixtures-rustleaks | Betterleaks 1.10.1 | 1805 | 1302 | 239 | 420 | 54 | 0.721 | 0.845 | 0.778 |
| fixtures-rustleaks | Betterleaks 2.0.0-rc.8 | 1906 | 1385 | 156 | 436 | 55 | 0.727 | 0.899 | 0.804 |
| fixtures-rustleaks | Kingfisher 2.19.1 | 627 | 539 | 1002 | 73 | 6 | 0.860 | 0.350 | 0.497 |
| fixtures-rustleaks-dotgit | Candidate | 0 | 0 | 30 | 0 | 0 | n/a | 0.000 | n/a |
| fixtures-rustleaks-dotgit | Rustleaks 0.1.0-alpha.12 | 0 | 0 | 30 | 0 | 0 | n/a | 0.000 | n/a |
| fixtures-rustleaks-dotgit | Gitleaks 8.30.1 | 0 | 0 | 30 | 0 | 0 | n/a | 0.000 | n/a |
| fixtures-rustleaks-dotgit | Betterleaks 1.10.1 | 0 | 0 | 30 | 0 | 0 | n/a | 0.000 | n/a |
| fixtures-rustleaks-dotgit | Betterleaks 2.0.0-rc.8 | 43 | 21 | 9 | 20 | 0 | 0.488 | 0.700 | 0.575 |
| fixtures-rustleaks-dotgit | Kingfisher 2.19.1 | 33 | 19 | 11 | 11 | 0 | 0.576 | 0.633 | 0.603 |
| heldout-quality (set 1) | Candidate | 2660 | 2135 | 383 | 360 | 25 | 0.803 | 0.848 | 0.825 |
| heldout-quality (set 1) | Rustleaks 0.1.0-alpha.12 | 2673 | 2135 | 383 | 360 | 25 | 0.799 | 0.848 | 0.823 |
| heldout-quality (set 1) | Gitleaks 8.30.1 | 2629 | 2100 | 418 | 366 | 25 | 0.799 | 0.834 | 0.816 |
| heldout-quality (set 1) | Betterleaks 1.10.1 | 2634 | 2057 | 461 | 397 | 57 | 0.781 | 0.817 | 0.799 |
| heldout-quality (set 1) | Betterleaks 2.0.0-rc.8 | 2779 | 2194 | 324 | 437 | 57 | 0.789 | 0.871 | 0.828 |
| heldout-quality (set 1) | Kingfisher 2.19.1 | 1693 | 1518 | 1000 | 101 | 1 | 0.897 | 0.603 | 0.721 |
| heldout-quality (set 2) | Candidate | 2211 | 1961 | 532 | 192 | 39 | 0.887 | 0.787 | 0.834 |
| heldout-quality (set 2) | Rustleaks 0.1.0-alpha.12 | 2211 | 1961 | 532 | 192 | 39 | 0.887 | 0.787 | 0.834 |
| heldout-quality (set 2) | Gitleaks 8.30.1 | 2065 | 1805 | 688 | 213 | 38 | 0.874 | 0.724 | 0.792 |
| heldout-quality (set 2) | Betterleaks 1.10.1 | 2162 | 1865 | 628 | 239 | 39 | 0.863 | 0.748 | 0.801 |
| heldout-quality (set 2) | Betterleaks 2.0.0-rc.8 | 2256 | 1930 | 563 | 279 | 37 | 0.855 | 0.774 | 0.813 |
| heldout-quality (set 2) | Kingfisher 2.19.1 | 1565 | 1446 | 1047 | 70 | 19 | 0.924 | 0.580 | 0.713 |

Notes:

- The candidate and 0.1.0-alpha.12 match the same labeled values on every
  workload. The candidate reports fewer findings on `fixtures-gitleaks`,
  `fixtures-betterleaks`, `fixtures-kingfisher-v1`, `fixtures-rustleaks` and
  held-out set 1, so its strict precision is equal or higher.
- The two Rustleaks builds share the highest F1 of the six tools on
  `constructed-v1` and held-out set 2. On held-out set 1, Betterleaks 2.0.0-rc.8 has a slightly
  higher F1 (0.828 against 0.825) and higher recall. Kingfisher has the
  highest precision and the lowest recall on all three.
- `fixtures-rustleaks-dotgit` places values inside `.git` folders.
  Rustleaks and Gitleaks skip `.git` in folder scans by design.
