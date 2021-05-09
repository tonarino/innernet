#!/usr/bin/env bash
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

OLD_VERSION="v$(cargo pkgid -p shared | cut -d '#' -f 2)"

cargo release "$1" --no-confirm --exclude "hostsfile" --exclude "publicip"

# re-stage the manpage commit and the cargo-release commit
git reset --soft @~1

cargo build

for binary in "innernet" "innernet-server"; do
    help2man --no-discard-stderr -s8 "target/debug/$binary" -N > "doc/$binary.8"
    gzip -fk "doc/$binary.8"
done

git add doc
perl -pi -e "s/$OLD_VERSION/$VERSION/g" README.md

VERSION="v$(cargo pkgid -p shared | cut -d '#' -f 2)"

git commit -m "meta: release $VERSION"
git tag -a "$VERSION" -m "release $VERSION"
