"""The program that the release dry run runs from an installed wheel.

Usage: python -I dryrun.py <path to bindings/python/pyproject.toml>

It checks that the installed metadata matches pyproject.toml, that the
package was imported from the virtual environment and not from the
repository, and that a scan of one synthetic AWS access key reports it.
"""

import importlib.metadata
import os
import sys
import tomllib

import rustleaks


def check_metadata(pyproject_path):
    with open(pyproject_path, "rb") as file:
        project = tomllib.load(file)["project"]
    metadata = importlib.metadata.metadata("rustleaks")
    expected = {
        "Name": project["name"],
        "Version": project["version"],
        "Summary": project["description"],
        "Requires-Python": project["requires-python"],
        "Metadata-Version": "2.4",
        "License-Expression": project["license"],
        "Keywords": ",".join(project["keywords"]),
    }
    for key, value in expected.items():
        if metadata[key] != value:
            sys.exit(f"wheel metadata {key} is {metadata[key]!r}, pyproject.toml says {value!r}")
    classifiers = metadata.get_all("Classifier") or []
    if classifiers != project["classifiers"]:
        sys.exit(f"wheel classifiers {classifiers} differ from pyproject.toml")
    urls = dict(line.split(", ", 1) for line in metadata.get_all("Project-URL") or [])
    if urls != project["urls"]:
        sys.exit(f"wheel project URLs {urls} differ from pyproject.toml")
    if rustleaks.__version__ != project["version"]:
        sys.exit(f"rustleaks.__version__ is {rustleaks.__version__}, not {project['version']}")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    location = os.path.dirname(os.path.abspath(rustleaks.__file__))
    if not location.startswith(os.path.abspath(sys.prefix)):
        sys.exit(f"rustleaks was imported from {location}, outside {sys.prefix}")
    check_metadata(sys.argv[1])
    # The key is built at run time so the repository self-scan does not
    # report this file.
    data = ('string AWSToken = "AKIA' + 'LALEMEL33243OLIB";\n').encode()
    with rustleaks.Engine() as engine:
        findings = engine.scan(data)
        rules = len(engine.rules())
    ids = [finding.rule_id for finding in findings]
    if "aws-access-token" not in ids:
        sys.exit(f"no aws-access-token finding in {ids}")
    print(f"found aws-access-token with {rules} rules loaded, rustleaks {rustleaks.__version__}")


if __name__ == "__main__":
    main()
