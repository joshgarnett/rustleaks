#!/bin/sh
# The executable is immutable; each invocation reads its own repository data.
set -eu

if [ "$#" -lt 2 ] || [ "$1" != "-C" ]; then
    printf '%s\n' 'expected -C and a synthetic repository directory' >&2
    exit 2
fi

fixture_directory=$2
cat "$fixture_directory/git-fixture.patch"
cat "$fixture_directory/git-fixture.stderr" >&2
IFS= read -r exit_code < "$fixture_directory/git-fixture.exit"
exit "$exit_code"
