# rustleaks for Python

The `rustleaks` package scans bytes and text for secrets, such as API keys
and passwords, with the Rustleaks engine. It runs in your process through a
native library that ships in the wheel. It needs CPython 3.12 or later and
uses only the standard library.

```python
import rustleaks

data = b'aws_key = "AKIALALEMEL33243OLIB"\n'  # rustleaks:allow
with rustleaks.Engine() as engine:
    for finding in engine.scan(data, path="config/app.env"):
        print(finding.rule_id, finding.start_line, finding.secret_range)
```

The value in the example is synthetic test data.

Read [Using Rustleaks from
Python](https://github.com/joshgarnett/rustleaks/blob/main/docs/user/python.md)
for rules, options, errors, threads, timeouts and safe logging. The package
is licensed under the MIT license.

The code lives in `bindings/python/` of
[joshgarnett/rustleaks](https://github.com/joshgarnett/rustleaks). Report
issues and send pull requests there.
