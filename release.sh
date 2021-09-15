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

OLD_VERSION="$(cargo pkgid -p shared | cut -d '#' -f 2)"

cargo release "$1" --no-confirm --exclude "hostsfile" --exclude "publicip" --execute

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

VERSION="$(cargo pkgid -p shared | cut -d '#' -f 2)"

perl -pi -e "s/v$OLD_VERSION/v$VERSION/g" README.md
perl -pi -e "s/$OLD_VERSION/$VERSION/g" wireguard-control/Cargo.toml

git add doc
git add README.md
git add wireguard-control/Cargo.toml
git commit -m "meta: release v$VERSION"
git tag -f -a "v$VERSION" -m "release v$VERSION"
