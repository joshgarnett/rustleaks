# Developer documentation

These pages are for contributors and maintainers. User documentation is in
[`docs/user/`](../user/). Contribution rules are in
[CONTRIBUTING.md](../../CONTRIBUTING.md).

## Code and tests

| Page | Read it to |
| --- | --- |
| [Architecture](architecture.md) | Learn the crates, how data moves between them, and where to add a rule, source, report format or flag |
| [Engine internals](engine-internals.md) | Change scan budgets, cancellation, caches, threads, Git processes or complete-target scanning |
| [Rule pack authoring](rule-pack-authoring.md) | Add or change a default rule or a Rustleaks rule file |
| [Testing](testing.md) | Run tests, add a test, and change the test data under `testdata/` |
| [Performance](performance.md) | Run the in-repository performance tools and keep their results |

## Scanner comparison

| Page | Read it to |
| --- | --- |
| [Scanner comparison](comparison.md) | Run the harness that compares Rustleaks with other scanners, and read the labels format |
| [Comparison workloads](comparison-workloads.md) | Fetch, generate and check the public repositories, synthetic workloads and fixture matrix |
| [Comparison quality inputs](comparison-quality.md) | Generate the constructed labeled corpus and convert Samsung CredData |

## Security, dependencies and releases

| Page | Read it to |
| --- | --- |
| [Threat model](threat-model.md) | See what is untrusted, the boundaries in the code and their known limits |
| [Security checks](security-checks.md) | Run the local security checks, fuzzing and self-scan, and see the hosted schedule |
| [Dependencies](dependencies.md) | Apply the dependency policy and the archive codec decisions |
| [Incident response](incident-response.md) | Handle a vulnerability, exposed credential or compromised input |
| [Releasing](releasing.md) | Check and publish a release |

Related folders: [`testdata/`](../../testdata/README.md) holds the test
corpora, copied fixtures and generated test files, and
[`docs/dependency-audits/`](../dependency-audits/README.md) holds the
dependency audits.
