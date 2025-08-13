#!/usr/bin/env bash
#
# TODO(Matej): rewrite this script to be a hook for `cargo-release`. I.e. swap the driving role
# between this script and cargo-release.

set -e

die () {
    echo >&2 "$@"
    exit 1
}

for command in help2man cargo-release sed; do
    if ! command -v $command &> /dev/null
    then
        echo "$command binary could not be found"
        exit
    fi
done

[ "$#" -eq 1 ] || die "usage: ./release.sh [patch|major|minor|rc]"
git diff --quiet || die 'ERROR: git repo is dirty.'

# pkgid gives a string like path+file:///home/strohel/work/innernet/shared#innernet-shared@1.7.0
OLD_VERSION="$(cargo pkgid -p innernet-shared | cut -d '@' -f 2)"

cargo release "$1" --no-publish --no-tag --no-push --no-confirm --execute

# re-stage the manpage commit and the cargo-release commit
git reset --soft @~1

cargo build

for binary in "innernet" "innernet-server"; do
    for shell in {fish,zsh,bash,powershell,elvish}; do
        "target/debug/$binary" completions $shell > doc/$binary.completions.$shell || die "CLI completion failed for $shell"
    done
    help2man --no-discard-stderr -s8 "target/debug/$binary" -N > "doc/$binary.8"
    gzip -fk "doc/$binary.8"
done

VERSION="$(cargo pkgid -p innernet-shared | cut -d '@' -f 2)"

git add doc
git commit -m "meta: release v$VERSION"
