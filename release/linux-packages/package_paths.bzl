"""Paths for the Linux release packages."""

DOC_ROOT = "usr/share/doc/rustleaks"

def document_directories(documents):
    """Returns the package directories that hold the given documents.

    Args:
      documents: source paths under `input/doc/`.

    Returns:
      The documentation root and every directory below it that holds a
      document, sorted.
    """
    directories = {DOC_ROOT: True}
    for path in documents:
        parts = path.removeprefix("input/doc/").split("/")[:-1]
        for index in range(len(parts)):
            directories[DOC_ROOT + "/" + "/".join(parts[:index + 1])] = True
    return sorted(directories.keys())
