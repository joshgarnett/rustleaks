# Scanner comparison results (2026-11)

These are the results of the runs fixed in [PROTOCOL.md](PROTOCOL.md), made
on 2026-11-19. They apply only to that host, those tool versions and those
inputs. Raw samples, reports and logs are private and are not in the
repository. The default rules changed after these runs (see the
[changelog](../../CHANGELOG.md)), so the quality rows describe the rules of
the measured builds.

## How to read the tables

- Each cell is median wall time, median peak RSS and the finding count of the
  last measured run, from 1 warmup and 3 measured runs. Quality runs use one
  run and report no time.
- "Rustleaks new" is the `rustleaks-main` build named in the protocol. It
  has `--jobs` (up to 12 detection threads by default) and parallel history
  and folder reading, which were released in 0.1.0-alpha.10. "Rustleaks
  0.1.0-alpha.9" was the latest release at the time of the runs.
- Finding counts are not comparable as a measure of quality. Tools use
  different rules, and Kingfisher reports each distinct value once by
  default. Quality is in its own section, measured against labels that no
  scanner produced.
- Memory is the peak RSS of the largest single process. In `git` mode that
  can be a `git` child; the history section also gives the scanner process
  alone.

## Deviations and failures

- **A hang in the measured Rustleaks build.** One of four bootstrap history
  samples of `rustleaks-main` did not finish and was stopped at the one-hour
  sample limit. The cause was a pipe that one `git log` process inherited
  from another when several threads started them at the same time on macOS
  (see the [threat model](../../docs/dev/threat-model.md#git-and-links)).
  The fix, which starts child processes one at a time, was in the build
  before it reached `main`. The protocol does not allow a code change within
  a comparison, so the tables below report the measured build as it ran, and
  the history scans of the fixed build are given separately under "History
  scans with the fixed build".
- **Rustleaks 0.1.0-alpha.9 history scans.** On croc, rails, django, ruby,
  lucene, bootstrap, prometheus, mongo and typescript, the release stopped at
  its limit on Git patch output ("Git patch output exceeded its configured
  byte ceiling") with exit code 1 and no findings. The harness counts these
  as failed cells. From 0.1.0-alpha.10, Rustleaks reads Git output while
  Git runs, and this limit no longer exists.
- R6 thread cells use 1, 4 and all threads, the harness default; R5 adds 12.
- No other cell failed, timed out or was skipped. The harness checked every
  tool hash before and after each run, and no other work ran on the host
  during the runs.

## Startup (R4c)

Warm cells:

| Workload | Rustleaks new | Rustleaks 0.1.0-alpha.9 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| tiny-clean-file | 28 ms, 17 MiB, 0 | 46 ms, 34 MiB, 0 | 172 ms, 65 MiB, 0 | 23 ms, 36 MiB, 0 | 35 ms, 38 MiB, 0 | 200 ms, 128 MiB, 0 |
| tiny-positive | 28 ms, 17 MiB, 1 | 46 ms, 34 MiB, 1 | 172 ms, 66 MiB, 1 | 23 ms, 36 MiB, 1 | 36 ms, 39 MiB, 1 | 218 ms, 142 MiB, 1 |
| tiny-clean-tree | 29 ms, 18 MiB, 0 | 46 ms, 34 MiB, 0 | 172 ms, 72 MiB, 0 | 23 ms, 38 MiB, 0 | 35 ms, 39 MiB, 0 | 202 ms, 130 MiB, 0 |

Cold cells (fresh `HOME`, empty tool caches):

| Workload | Rustleaks new | Rustleaks 0.1.0-alpha.9 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| tiny-clean-file | 28 ms, 17 MiB, 0 | 46 ms, 34 MiB, 0 | 172 ms, 68 MiB, 0 | 154 ms, 51 MiB, 0 | 166 ms, 53 MiB, 0 | 2.26 s, 193 MiB, 0 |
| tiny-positive | 28 ms, 17 MiB, 1 | 47 ms, 34 MiB, 1 | 172 ms, 66 MiB, 1 | 153 ms, 52 MiB, 1 | 167 ms, 53 MiB, 1 | 2.28 s, 207 MiB, 1 |
| tiny-clean-tree | 29 ms, 18 MiB, 0 | 46 ms, 34 MiB, 0 | 173 ms, 71 MiB, 0 | 155 ms, 52 MiB, 0 | 168 ms, 53 MiB, 0 | 2.27 s, 191 MiB, 0 |

Kingfisher takes about 2.3 s with a fresh `HOME` and about 0.2 s once its
cache exists.

## Folder scans of public repositories (R1)

| Workload | Rustleaks new | Rustleaks 0.1.0-alpha.9 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| croc | 40 ms, 49 MiB, 5 | 88 ms, 40 MiB, 5 | 289 ms, 99 MiB, 5 | 283 ms, 97 MiB, 65 | 255 ms, 101 MiB, 65 | 217 ms, 139 MiB, 0 |
| flask | 35 ms, 35 MiB, 6 | 62 ms, 38 MiB, 6 | 221 ms, 87 MiB, 6 | 127 ms, 80 MiB, 6 | 164 ms, 84 MiB, 6 | 208 ms, 137 MiB, 0 |
| jq | 39 ms, 41 MiB, 0 | 76 ms, 38 MiB, 0 | 255 ms, 101 MiB, 0 | 200 ms, 82 MiB, 0 | 165 ms, 98 MiB, 0 | 251 ms, 161 MiB, 0 |
| select2 | 41 ms, 38 MiB, 0 | 75 ms, 40 MiB, 0 | 265 ms, 100 MiB, 0 | 134 ms, 87 MiB, 0 | 179 ms, 97 MiB, 0 | 222 ms, 139 MiB, 0 |
| rails | 125 ms, 86 MiB, 25 | 364 ms, 45 MiB, 25 | 1.64 s, 119 MiB, 25 | 476 ms, 132 MiB, 134 | 531 ms, 140 MiB, 151 | 366 ms, 162 MiB, 7 |
| django | 182 ms, 91 MiB, 8 | 508 ms, 46 MiB, 8 | 2.11 s, 123 MiB, 8 | 533 ms, 148 MiB, 425 | 676 ms, 162 MiB, 427 | 514 ms, 161 MiB, 2 |
| ruby | 256 ms, 99 MiB, 69 | 603 ms, 48 MiB, 69 | 4.46 s, 129 MiB, 69 | 550 ms, 141 MiB, 141 | 615 ms, 152 MiB, 144 | 555 ms, 273 MiB, 49 |
| lucene | 269 ms, 96 MiB, 21 | 893 ms, 48 MiB, 21 | 3.75 s, 129 MiB, 21 | 886 ms, 163 MiB, 20 | 685 ms, 177 MiB, 20 | 4.96 s, 204 MiB, 0 |
| bootstrap | 49 ms, 49 MiB, 0 | 114 ms, 40 MiB, 0 | 760 ms, 118 MiB, 0 | 140 ms, 101 MiB, 0 | 183 ms, 109 MiB, 0 | 225 ms, 143 MiB, 0 |
| prometheus | 81 ms, 84 MiB, 20 | 238 ms, 43 MiB, 20 | 1.43 s, 119 MiB, 20 | 443 ms, 124 MiB, 376 | 384 ms, 131 MiB, 377 | 265 ms, 249 MiB, 24 |
| gitlab | 2.67 s, 333 MiB, 404 | 7.62 s, 85 MiB, 404 | 54.3 s, 173 MiB, 404 | 8.76 s, 195 MiB, 1226 | 5.43 s, 206 MiB, 1318 | 6.83 s, 2395 MiB, 110 |
| mongo | 1.35 s, 177 MiB, 1059 | 4.16 s, 68 MiB, 1059 | 57.7 s, 158 MiB, 1059 | 1.71 s, 179 MiB, 517 | 1.99 s, 196 MiB, 1326 | 2.03 s, 356 MiB, 229 |
| typescript | 2.25 s, 123 MiB, 48 | 4.34 s, 53 MiB, 48 | 33.9 s, 151 MiB, 48 | 2.11 s, 154 MiB, 2 | 2.34 s, 169 MiB, 9 | 4.31 s, 192 MiB, 0 |
| linux | 2.58 s, 173 MiB, 242 | 9.75 s, 59 MiB, 242 | 182 s, 157 MiB, 242 | 2.64 s, 180 MiB, 78 | 2.72 s, 187 MiB, 86 | 3.14 s, 349 MiB, 6 |

Rustleaks new is the fastest on 13 of 14 repositories. On typescript
(136,381 files) Betterleaks 1.10.1 is 6% faster. Rustleaks new uses more
memory than 0.1.0-alpha.9 because it runs up to 12 detection threads. On
gitlab, mongo and linux, Gitleaks uses less memory than Rustleaks new; on
the other 11 repositories, Rustleaks new uses the least of the five current
tools.

## History scans of public repositories (R2)

| Workload | Rustleaks new | Rustleaks 0.1.0-alpha.9 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| croc | 458 ms, 84 MiB, 21 | failed | 925 ms, 100 MiB, 21 | 780 ms, 110 MiB, 93 | 357 ms, 258 MiB, 93 | 334 ms, 213 MiB, 0 |
| flask | 192 ms, 61 MiB, 12 | 439 ms, 108 MiB, 12 | 571 ms, 109 MiB, 12 | 430 ms, 108 MiB, 29 | 299 ms, 379 MiB, 29 | 373 ms, 219 MiB, 0 |
| jq | 212 ms, 61 MiB, 0 | 402 ms, 82 MiB, 0 | 614 ms, 108 MiB, 0 | 362 ms, 95 MiB, 0 | 250 ms, 304 MiB, 0 | 402 ms, 218 MiB, 0 |
| select2 | 272 ms, 98 MiB, 0 | 864 ms, 146 MiB, 0 | 2.69 s, 171 MiB, 0 | 622 ms, 135 MiB, 0 | 330 ms, 530 MiB, 0 | 541 ms, 220 MiB, 0 |
| rails | 3.36 s, 254 MiB, 95 | failed | 11.3 s, 621 MiB, 95 | 10.1 s, 571 MiB, 456 | 3.21 s, 1337 MiB, 576 | 3.72 s, 1303 MiB, 14 |
| django | 3.55 s, 158 MiB, 18 | failed | 12.5 s, 479 MiB, 18 | 8.88 s, 482 MiB, 1088 | 2.67 s, 1143 MiB, 1093 | 1.93 s, 971 MiB, 2 |
| ruby | 6.09 s, 282 MiB, 155 | failed | 24.7 s, 1011 MiB, 155 | 23.1 s, 833 MiB, 426 | 6.02 s, 2280 MiB, 441 | 8.33 s, 1606 MiB, 92 |
| lucene | 4.50 s, 321 MiB, 120 | failed | 56.5 s, 843 MiB, 120 | 16.8 s, 763 MiB, 204 | 4.80 s, 1364 MiB, 221 | 4.28 s, 1436 MiB, 8 |
| bootstrap | 3.75 s, 338 MiB, 7 (1 failed) | failed | 111 s, 572 MiB, 7 | 10.8 s, 465 MiB, 7 | 4.20 s, 1229 MiB, 9 | 1.19 s, 902 MiB, 0 |
| prometheus | 2.27 s, 324 MiB, 34 | failed | 7.10 s, 663 MiB, 34 | 6.52 s, 647 MiB, 1229 | 2.59 s, 1277 MiB, 1232 | 1.08 s, 1233 MiB, 28 |
| mongo | 18.7 s, 980 MiB, 3210 | failed | 196 s, 1946 MiB, 3210 | 61.9 s, 1768 MiB, 1292 | 19.0 s, 2240 MiB, 3909 | 11.6 s, 2849 MiB, 720 |
| typescript | 28.2 s, 934 MiB, 432 | failed | 183 s, 2734 MiB, 432 | 76.3 s, 2483 MiB, 25 | 24.4 s, 3485 MiB, 80 | 44.8 s, 3653 MiB, 0 |

Scanner process alone (sampled every 10 ms), for the largest histories:

| Workload | Rustleaks new | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- |
| rails | 247 MiB | 463 MiB | 284 MiB | 1347 MiB | 1297 MiB |
| ruby | 188 MiB | 162 MiB | 146 MiB | 2255 MiB | 1587 MiB |
| mongo | 975 MiB | 809 MiB | 373 MiB | 2236 MiB | 2953 MiB |
| typescript | 946 MiB | 1262 MiB | 682 MiB | 3548 MiB | 3863 MiB |

Fastest tool per repository: Kingfisher on 6 (croc, django, lucene,
bootstrap, prometheus, mongo), Betterleaks 2.0.0-rc.8 on 3 (rails, ruby,
typescript) and Rustleaks new on 3 (flask, jq, select2). Rustleaks new is
within 10% of Betterleaks 2.0.0-rc.8 or faster on every history except
croc, django and typescript, and uses 12% to 44% of its peak memory.

Kingfisher scans blobs, while Gitleaks, Betterleaks and Rustleaks scan each
commit's patch (see the scope differences in the protocol). It reports
different findings: none on bootstrap and typescript, where the patch
scanners report 7 to 432. Rustleaks scans patches, like Gitleaks.

## History scans with the fixed build

After the fix reached `main`, the R2 command was run again on the same
day with the `main` build (SHA-256
`e274ffe6e06c389035aef21b2aad54cf93d666a364700f07683d3691caab2fb4`, the same
tree as `main` at `164243b`), with Betterleaks 2.0.0-rc.8 and Kingfisher
2.19.1 as references for the conditions. All 180 samples finished. Before
it, 320 bootstrap history scans of the fixed build, 8 at a time, all
finished with the expected 7 findings.

| Workload | Rustleaks new (R2) | Rustleaks fixed | Betterleaks 2.0.0-rc.8 (R2, rerun) | Kingfisher 2.19.1 (R2, rerun) |
| --- | --- | --- | --- | --- |
| croc | 458 ms, 84 MiB, 21 | 443 ms, 86 MiB, 21 | 357 ms, 383 ms | 334 ms, 334 ms |
| flask | 192 ms, 61 MiB, 12 | 189 ms, 62 MiB, 12 | 299 ms, 313 ms | 373 ms, 379 ms |
| jq | 212 ms, 61 MiB, 0 | 210 ms, 60 MiB, 0 | 250 ms, 255 ms | 402 ms, 404 ms |
| select2 | 272 ms, 98 MiB, 0 | 276 ms, 103 MiB, 0 | 330 ms, 329 ms | 541 ms, 547 ms |
| rails | 3.36 s, 254 MiB, 95 | 3.35 s, 255 MiB, 95 | 3.21 s, 3.20 s | 3.72 s, 3.73 s |
| django | 3.55 s, 158 MiB, 18 | 3.56 s, 160 MiB, 18 | 2.67 s, 2.66 s | 1.93 s, 1.93 s |
| ruby | 6.09 s, 282 MiB, 155 | 6.01 s, 268 MiB, 155 | 6.02 s, 5.96 s | 8.33 s, 8.34 s |
| lucene | 4.50 s, 321 MiB, 120 | 4.42 s, 327 MiB, 120 | 4.80 s, 4.80 s | 4.28 s, 4.28 s |
| bootstrap | 3.75 s, 338 MiB, 7 (1 failed) | 3.79 s, 340 MiB, 7 | 4.20 s, 4.31 s | 1.19 s, 1.19 s |
| prometheus | 2.27 s, 324 MiB, 34 | 2.26 s, 332 MiB, 34 | 2.59 s, 2.56 s | 1.08 s, 1.08 s |
| mongo | 18.7 s, 980 MiB, 3210 | 18.7 s, 993 MiB, 3210 | 19.0 s, 19.3 s | 11.6 s, 11.6 s |
| typescript | 28.2 s, 934 MiB, 432 | 28.1 s, 907 MiB, 432 | 24.4 s, 24.4 s | 44.8 s, 44.9 s |

Kingfisher ran within 1.5% of its R2 times, and Betterleaks 2.0.0-rc.8
within 3% except on croc (7%) and flask (5%), which take under 0.4 s. The
fixed build ran within 3.5% of the measured build, with the same findings,
and within 2% on every repository that takes more than 0.5 s. The process
start lock did not measurably change history scan speed.

## Synthetic workloads (R4)

Geometric mean of each tool's median wall time and peak RSS divided by
Rustleaks new, over the workloads in each group:

| Group | Workloads | Rustleaks new | Rustleaks 0.1.0-alpha.9 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| Not tuned | 52 | time 1.00x, memory 1.00x | time 1.97x, memory 1.79x | time 8.83x, memory 3.12x | time 5.24x, memory 5.57x | time 5.27x, memory 2.95x | time 6.32x, memory 6.16x |
| Tuned on by Rustleaks | 18 | time 1.00x, memory 1.00x | time 1.58x, memory 1.73x | time 4.92x, memory 3.78x | time 1.26x, memory 2.52x | time 1.43x, memory 2.61x | time 5.66x, memory 7.29x |

Workloads where another tool was more than 10% faster than Rustleaks new:

| Workload | Group | Faster tool | Its time | Rustleaks new |
| --- | --- | --- | --- | --- |
| entropy-negatives-1024mib | not tuned | Kingfisher 2.19.1 | 400 ms | 1.01 s |
| git-many-small-files | not tuned | Betterleaks 2.0.0-rc.8 | 107 ms | 133 ms |
| keyword-dense-1024mib | not tuned | Kingfisher 2.19.1 | 604 ms | 1.48 s |
| minified-1024mib | not tuned | Betterleaks 1.10.1 | 687 ms | 1.01 s |
| files-100000 | tuned | Betterleaks 2.0.0-rc.8 | 982 ms | 1.20 s |
| git-20000 | tuned | Betterleaks 2.0.0-rc.8 | 185 ms | 231 ms |
| git-current-tree-control | tuned | Betterleaks 1.10.1 | 27 ms | 32 ms |
| mixed-clean-4mib | tuned | Betterleaks 1.10.1 | 36 ms | 40 ms |
| tiny-clean-file | tuned | Betterleaks 1.10.1 | 26 ms | 32 ms |
| tiny-clean-tree | tuned | Betterleaks 1.10.1 | 27 ms | 31 ms |
| tiny-positive | tuned | Betterleaks 1.10.1 | 26 ms | 32 ms |

## Thread scaling (R5)

Each tool runs with the same thread count through its own setting, as
recorded by the harness. Median wall time:

rails, `git` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Rustleaks new | 8.88 s | 4.46 s | 3.37 s | 3.35 s |
| Gitleaks 8.30.1 | 10.6 s | 9.03 s | 9.59 s | 11.1 s |
| Betterleaks 1.10.1 | 10.6 s | 9.95 s | 10.1 s | 10.1 s |
| Betterleaks 2.0.0-rc.8 | 9.92 s | 3.22 s | 3.12 s | 3.17 s |
| Kingfisher 2.19.1 | 19.8 s | 7.50 s | 4.60 s | 3.73 s |

django, `git` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Rustleaks new | 7.81 s | 3.57 s | 3.59 s | 2.75 s |
| Gitleaks 8.30.1 | 11.1 s | 8.91 s | 10.7 s | 12.6 s |
| Betterleaks 1.10.1 | 8.99 s | 8.69 s | 8.83 s | 8.86 s |
| Betterleaks 2.0.0-rc.8 | 10.7 s | 3.21 s | 2.58 s | 2.72 s |
| Kingfisher 2.19.1 | 14.8 s | 4.93 s | 2.64 s | 1.92 s |

rails, `dir` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Rustleaks new | 358 ms | 152 ms | 125 ms | 130 ms |
| Gitleaks 8.30.1 | 1.26 s | 611 ms | 1.27 s | 1.67 s |
| Betterleaks 1.10.1 | 748 ms | 316 ms | 452 ms | 449 ms |
| Betterleaks 2.0.0-rc.8 | 630 ms | 288 ms | 514 ms | 551 ms |
| Kingfisher 2.19.1 | 527 ms | 404 ms | 361 ms | 360 ms |

django, `dir` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Rustleaks new | 501 ms | 220 ms | 183 ms | 189 ms |
| Gitleaks 8.30.1 | 1.71 s | 757 ms | 1.60 s | 2.08 s |
| Betterleaks 1.10.1 | 1.11 s | 379 ms | 470 ms | 558 ms |
| Betterleaks 2.0.0-rc.8 | 915 ms | 367 ms | 595 ms | 702 ms |
| Kingfisher 2.19.1 | 730 ms | 546 ms | 487 ms | 508 ms |

keyword-dense-16mib, `dir` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Rustleaks new | 147 ms | 68 ms | 57 ms | 62 ms |
| Gitleaks 8.30.1 | 856 ms | 556 ms | 778 ms | 1.05 s |
| Betterleaks 1.10.1 | 1.05 s | 435 ms | 727 ms | 1.27 s |
| Betterleaks 2.0.0-rc.8 | 1.10 s | 439 ms | 665 ms | 1.23 s |
| Kingfisher 2.19.1 | 305 ms | 242 ms | 227 ms | 229 ms |

mixed-source-16mib, `dir` mode:

| Tool | 1 | 4 | 12 | 36 |
| --- | --- | --- | --- | --- |
| Rustleaks new | 95 ms | 51 ms | 46 ms | 45 ms |
| Gitleaks 8.30.1 | 1.72 s | 321 ms | 423 ms | 491 ms |
| Betterleaks 1.10.1 | 460 ms | 217 ms | 275 ms | 348 ms |
| Betterleaks 2.0.0-rc.8 | 450 ms | 225 ms | 312 ms | 345 ms |
| Kingfisher 2.19.1 | 301 ms | 241 ms | 239 ms | 243 ms |

Rustleaks new runs one `git log` process per thread, up to 6, and two
folder reader threads. Its folder scans of rails and django were no faster
at 36 threads than at 12.

## Held-out set (R6)

Sealed inputs that no Rustleaks change was tuned on.

| Workload | Rustleaks new | Rustleaks 0.1.0-alpha.9 | Gitleaks 8.30.1 | Betterleaks 1.10.1 | Betterleaks 2.0.0-rc.8 | Kingfisher 2.19.1 |
| --- | --- | --- | --- | --- | --- | --- |
| heldout-perf-10m | 56 ms, 32 MiB, 11 | 90 ms, 36 MiB, 11 | 548 ms, 104 MiB, 11 | 214 ms, 112 MiB, 11 | 277 ms, 117 MiB, 12 | 247 ms, 181 MiB, 8 |
| heldout-perf-100m | 129 ms, 50 MiB, 87 | 265 ms, 43 MiB, 87 | 2.68 s, 116 MiB, 87 | 922 ms, 136 MiB, 82 | 886 ms, 158 MiB, 89 | 590 ms, 275 MiB, 62 |
| heldout-perf-500m | 453 ms, 72 MiB, 268 | 1.47 s, 47 MiB, 268 | 10.3 s, 121 MiB, 268 | 1.86 s, 142 MiB, 273 | 1.77 s, 179 MiB, 289 | 694 ms, 498 MiB, 203 |
| heldout-git | 115 ms, 58 MiB, 102 | 244 ms, 59 MiB, 102 | 439 ms, 97 MiB, 102 | 438 ms, 108 MiB, 101 | 440 ms, 214 MiB, 112 | 329 ms, 195 MiB, 66 |

## Quality (R7 and R7h)

Precision counts labeled findings only; "On negatives" is findings on values
labeled as not secret; "Unlabeled" is findings on text with no label.

| Workload | Tool | Found | Missed | On negatives | Unlabeled | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| constructed-v1 | Rustleaks new | 871 | 228 | 114 | 0 | 0.884 | 0.793 | 0.836 |
| constructed-v1 | Rustleaks 0.1.0-alpha.9 | 871 | 228 | 114 | 0 | 0.884 | 0.793 | 0.836 |
| constructed-v1 | Gitleaks 8.30.1 | 871 | 228 | 114 | 0 | 0.884 | 0.793 | 0.836 |
| constructed-v1 | Betterleaks 1.10.1 | 940 | 159 | 126 | 0 | 0.882 | 0.855 | 0.868 |
| constructed-v1 | Betterleaks 2.0.0-rc.8 | 972 | 127 | 138 | 0 | 0.876 | 0.884 | 0.880 |
| constructed-v1 | Kingfisher 2.19.1 | 669 | 430 | 3 | 0 | 0.996 | 0.609 | 0.756 |
| fixtures-betterleaks | Rustleaks new | 926 | 176 | 162 | 101 | 0.851 | 0.840 | 0.846 |
| fixtures-betterleaks | Rustleaks 0.1.0-alpha.9 | 926 | 176 | 162 | 101 | 0.851 | 0.840 | 0.846 |
| fixtures-betterleaks | Gitleaks 8.30.1 | 926 | 176 | 162 | 101 | 0.851 | 0.840 | 0.846 |
| fixtures-betterleaks | Betterleaks 1.10.1 | 1074 | 28 | 143 | 95 | 0.882 | 0.975 | 0.926 |
| fixtures-betterleaks | Betterleaks 2.0.0-rc.8 | 1102 | 0 | 156 | 95 | 0.876 | 1.000 | 0.934 |
| fixtures-betterleaks | Kingfisher 2.19.1 | 782 | 320 | 18 | 59 | 0.978 | 0.710 | 0.822 |
| fixtures-gitleaks | Rustleaks new | 6393 | 0 | 30 | 0 | 0.995 | 1.000 | 0.998 |
| fixtures-gitleaks | Rustleaks 0.1.0-alpha.9 | 6393 | 0 | 30 | 0 | 0.995 | 1.000 | 0.998 |
| fixtures-gitleaks | Gitleaks 8.30.1 | 6393 | 0 | 30 | 0 | 0.995 | 1.000 | 0.998 |
| fixtures-gitleaks | Betterleaks 1.10.1 | 6113 | 280 | 30 | 0 | 0.995 | 0.956 | 0.975 |
| fixtures-gitleaks | Betterleaks 2.0.0-rc.8 | 6269 | 124 | 32 | 0 | 0.995 | 0.981 | 0.988 |
| fixtures-gitleaks | Kingfisher 2.19.1 | 516 | 5877 | 7 | 0 | 0.987 | 0.081 | 0.149 |
| fixtures-kingfisher | Rustleaks new | 1 | 11 | 9 | 0 | 0.100 | 0.083 | 0.091 |
| fixtures-kingfisher | Rustleaks 0.1.0-alpha.9 | 1 | 11 | 9 | 0 | 0.100 | 0.083 | 0.091 |
| fixtures-kingfisher | Gitleaks 8.30.1 | 1 | 11 | 9 | 0 | 0.100 | 0.083 | 0.091 |
| fixtures-kingfisher | Betterleaks 1.10.1 | 7 | 5 | 9 | 0 | 0.438 | 0.583 | 0.500 |
| fixtures-kingfisher | Betterleaks 2.0.0-rc.8 | 7 | 5 | 9 | 0 | 0.438 | 0.583 | 0.500 |
| fixtures-kingfisher | Kingfisher 2.19.1 | 12 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| fixtures-kingfisher-v1 | Rustleaks new | 1098 | 1040 | 8 | 0 | 0.993 | 0.514 | 0.677 |
| fixtures-kingfisher-v1 | Rustleaks 0.1.0-alpha.9 | 1098 | 1040 | 8 | 0 | 0.993 | 0.514 | 0.677 |
| fixtures-kingfisher-v1 | Gitleaks 8.30.1 | 1098 | 1040 | 8 | 0 | 0.993 | 0.514 | 0.677 |
| fixtures-kingfisher-v1 | Betterleaks 1.10.1 | 1195 | 943 | 8 | 0 | 0.993 | 0.559 | 0.715 |
| fixtures-kingfisher-v1 | Betterleaks 2.0.0-rc.8 | 1250 | 888 | 8 | 0 | 0.994 | 0.585 | 0.736 |
| fixtures-kingfisher-v1 | Kingfisher 2.19.1 | 497 | 1641 | 2 | 0 | 0.996 | 0.232 | 0.377 |
| fixtures-rustleaks | Rustleaks new | 116 | 1425 | 175 | 60 | 0.399 | 0.075 | 0.127 |
| fixtures-rustleaks | Rustleaks 0.1.0-alpha.9 | 116 | 1425 | 175 | 60 | 0.399 | 0.075 | 0.127 |
| fixtures-rustleaks | Gitleaks 8.30.1 | 116 | 1425 | 178 | 60 | 0.395 | 0.075 | 0.126 |
| fixtures-rustleaks | Betterleaks 1.10.1 | 1302 | 239 | 420 | 54 | 0.756 | 0.845 | 0.798 |
| fixtures-rustleaks | Betterleaks 2.0.0-rc.8 | 1385 | 156 | 436 | 55 | 0.761 | 0.899 | 0.824 |
| fixtures-rustleaks | Kingfisher 2.19.1 | 539 | 1002 | 72 | 7 | 0.882 | 0.350 | 0.501 |
| fixtures-rustleaks-dotgit | Rustleaks new | 0 | 30 | 0 | 0 | n/a | 0.000 | n/a |
| fixtures-rustleaks-dotgit | Rustleaks 0.1.0-alpha.9 | 0 | 30 | 0 | 0 | n/a | 0.000 | n/a |
| fixtures-rustleaks-dotgit | Gitleaks 8.30.1 | 0 | 30 | 0 | 0 | n/a | 0.000 | n/a |
| fixtures-rustleaks-dotgit | Betterleaks 1.10.1 | 0 | 30 | 0 | 0 | n/a | 0.000 | n/a |
| fixtures-rustleaks-dotgit | Betterleaks 2.0.0-rc.8 | 21 | 9 | 20 | 0 | 0.512 | 0.700 | 0.592 |
| fixtures-rustleaks-dotgit | Kingfisher 2.19.1 | 16 | 14 | 15 | 0 | 0.516 | 0.533 | 0.525 |
| heldout-quality | Rustleaks new | 2101 | 417 | 366 | 25 | 0.852 | 0.834 | 0.843 |
| heldout-quality | Rustleaks 0.1.0-alpha.9 | 2101 | 417 | 366 | 25 | 0.852 | 0.834 | 0.843 |
| heldout-quality | Gitleaks 8.30.1 | 2100 | 418 | 366 | 25 | 0.852 | 0.834 | 0.843 |
| heldout-quality | Betterleaks 1.10.1 | 2057 | 461 | 397 | 57 | 0.838 | 0.817 | 0.827 |
| heldout-quality | Betterleaks 2.0.0-rc.8 | 2194 | 324 | 437 | 57 | 0.834 | 0.871 | 0.852 |
| heldout-quality | Kingfisher 2.19.1 | 1518 | 1000 | 101 | 1 | 0.938 | 0.603 | 0.734 |

Notes:

- On `constructed-v1`, the Gitleaks fixtures and the Betterleaks and
  Kingfisher fixtures, Rustleaks new and Gitleaks find the same values. On
  `constructed-v1` and the held-out set, Betterleaks 2.0.0-rc.8 has the
  highest recall and Kingfisher the highest precision and lowest recall.
- Kingfisher has the best scores on its own current examples
  (`fixtures-kingfisher`) but low recall on its older examples
  (`fixtures-kingfisher-v1`) and on the Gitleaks examples.
- The `fixtures-rustleaks` rows use default settings, where Rustleaks'
  native rule packs are off, so its recall there is the Gitleaks default
  rules' recall.
- `fixtures-rustleaks-dotgit` places values inside `.git` folders. Gitleaks
  and Rustleaks skip `.git` in folder scans by design.

## Findings that differ from Gitleaks

Rustleaks new and Gitleaks 8.30.1 reported the same number of findings in
all 106 folder, history, synthetic, startup and held-out performance cells.
The quality runs, which match each value, found two differences:

- **`rustleaks:allow`.** In `fixtures-rustleaks`, Gitleaks reports 3 values
  that Rustleaks does not. Each line carries a `rustleaks:allow` comment,
  which Rustleaks treats like `gitleaks:allow`. This is documented in
  [Moving from Gitleaks](../../docs/user/moving-from-gitleaks.md#findings-that-can-differ).
- **File names that look like archives.** In the held-out set, Rustleaks
  reports one value in `docker-compose.branch.yml` that Gitleaks does not.
  With the default `--max-archive-depth 0`, Gitleaks skips every file whose
  name contains an archive or compression extension anywhere, such as `.br`
  in `.branch`, `.gz` or `.zip`, without reading it. Rustleaks reads these
  files as plain text at depth 0. Rustleaks 0.1.0-alpha.9 behaves the same
  way. This behavior is intended and is listed in
  [Moving from Gitleaks](../../docs/user/moving-from-gitleaks.md#findings-that-can-differ).
  No Rustleaks code changed in response to the held-out result.
