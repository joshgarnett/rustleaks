"""Builds and checks the PyPI upload form of a wheel, and uploads it.

Usage:
  python -I upload.py check <wheel> <pyproject.toml>
  python -I upload.py upload <wheel> <pyproject.toml> <upload URL>

PyPI creates a release's metadata from the upload form, not from the
wheel's METADATA file, and that metadata cannot be changed later. So the
form carries every core metadata field of the wheel, and `check` requires
each one to be present and to match pyproject.toml. The release dry run
runs `check`; `Publish Python Package` runs `upload`, with the upload token
in the PYPI_TOKEN environment variable. Standard library only.
"""

import base64
import email.parser
import hashlib
import os
import sys
import tomllib
import urllib.request
import uuid
import zipfile


def read_metadata(wheel):
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        dist_info = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(dist_info) != 1:
            sys.exit(f"{wheel} has {len(dist_info)} METADATA files")
        text = archive.read(dist_info[0]).decode("utf-8")
        licenses = dist_info[0].removesuffix("METADATA") + "licenses/"
        license_files = {name.removeprefix(licenses) for name in names if name.startswith(licenses)}
    return email.parser.Parser().parsestr(text), license_files


def form_fields(wheel):
    """Returns the upload form as (name, value) pairs, without the file."""
    metadata, _ = read_metadata(wheel)
    with open(wheel, "rb") as file:
        digest = hashlib.sha256(file.read()).hexdigest()
    fields = [
        (":action", "file_upload"),
        ("protocol_version", "1"),
        ("metadata_version", metadata["Metadata-Version"]),
        ("name", metadata["Name"]),
        ("version", metadata["Version"]),
        ("summary", metadata["Summary"]),
        ("description", metadata.get_payload()),
        ("description_content_type", metadata["Description-Content-Type"]),
        ("requires_python", metadata["Requires-Python"]),
        ("license_expression", metadata["License-Expression"]),
        ("keywords", metadata["Keywords"]),
        ("filetype", "bdist_wheel"),
        ("pyversion", "py3"),
        ("sha256_digest", digest),
    ]
    fields += [("license_files", value) for value in metadata.get_all("License-File") or []]
    fields += [("classifiers", value) for value in metadata.get_all("Classifier") or []]
    fields += [("project_urls", value) for value in metadata.get_all("Project-URL") or []]
    return fields


def check(wheel, pyproject_path):
    with open(pyproject_path, "rb") as file:
        project = tomllib.load(file)["project"]
    readme_path = os.path.join(os.path.dirname(pyproject_path), project["readme"])
    with open(readme_path, encoding="utf-8") as file:
        readme = file.read()
    fields = form_fields(wheel)
    single = {}
    for name, value in fields:
        if value is None or value == "":
            sys.exit(f"upload form field {name} is empty")
        single.setdefault(name, value)
    _, license_files = read_metadata(wheel)
    expected = {
        "metadata_version": "2.4",
        "name": project["name"],
        "version": project["version"],
        "summary": project["description"],
        "description": readme,
        "description_content_type": "text/markdown",
        "requires_python": project["requires-python"],
        "license_expression": project["license"],
        "keywords": ",".join(project["keywords"]),
    }
    for name, value in expected.items():
        actual = single.get(name)
        if name == "description":
            # The metadata writer ends the body with one extra line break.
            actual, value = actual.rstrip("\n"), value.rstrip("\n")
        if actual != value:
            sys.exit(f"upload form field {name} is {actual!r:.80}, expected {value!r:.80}")
    lists = {
        "classifiers": project["classifiers"],
        "project_urls": [f"{label}, {url}" for label, url in project["urls"].items()],
    }
    for name, values in lists.items():
        actual = [value for field, value in fields if field == name]
        if sorted(actual) != sorted(values):
            sys.exit(f"upload form field {name} is {actual}, expected {values}")
    listed = {value for field, value in fields if field == "license_files"}
    if not listed or listed != license_files:
        sys.exit(f"License-File entries {sorted(listed)} differ from the wheel's licenses folder")
    for required in ("LICENSE", "NOTICE", "third-party/index.json"):
        if required not in listed:
            sys.exit(f"the wheel has no .dist-info/licenses/{required}")
    print(f"upload form of {os.path.basename(wheel)}: {len(fields)} fields match pyproject.toml")


def upload(wheel, pyproject_path, url):
    check(wheel, pyproject_path)
    token = os.environ["PYPI_TOKEN"]
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in form_fields(wheel):
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    with open(wheel, "rb") as file:
        content = file.read()
    filename = os.path.basename(wheel)
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="content"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n".encode()
        + content
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    credentials = base64.b64encode(f"__token__:{token}".encode()).decode()
    request = urllib.request.Request(
        url,
        data=b"".join(parts),
        method="POST",
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "rustleaks-release/0.1",
        },
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        if response.status != 200:
            sys.exit(f"upload of {filename} returned HTTP {response.status}")
    print(f"uploaded {filename}")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "check":
        check(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 5 and sys.argv[1] == "upload":
        upload(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
