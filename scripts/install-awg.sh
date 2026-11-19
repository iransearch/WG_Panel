#!/usr/bin/env bash
# Build the pinned AmneziaWG 3.1 control tools and userspace runtime.
set -euo pipefail

tools_tag=v3.1.20260812
tools_revision=ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
runtime_tag=v3.1.20261116
runtime_revision=08fe3d33bbb116be09a6183d02609311b8b0c9e8
go_version=1.25.14
destdir=${1:-}

if [[ -z $destdir && $(id -u) != 0 ]]; then
    echo 'Run this installer with sudo, or pass a staging directory.' >&2
    exit 1
fi

for program in git make cc curl tar sha256sum; do
    if ! command -v "$program" >/dev/null; then
        echo "Missing $program. Install build-essential, git and curl before running this script." >&2
        exit 1
    fi
done

workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT
export GOTOOLCHAIN=local

if ! go env GOVERSION 2>/dev/null | grep -Eq '^go1\.(2[5-9]|[3-9][0-9])([.]|$)'; then
    case "$(uname -m)" in
        x86_64)
            arch=amd64
            digest=a21ae5633a269bcd7e90cf767e48225633795e99d831742cbf3397064fee7712
            ;;
        aarch64)
            arch=arm64
            digest=9bf234ea70ffec9347fdf6b22ce4add51717d3386a38a441e8c8743fceb5eaee
            ;;
        *)
            echo 'Install Go 1.25 or newer first on this architecture.' >&2
            exit 1
            ;;
    esac
    archive="$workdir/go.tar.gz"
    curl -fL --retry 3 --max-time 180 "https://go.dev/dl/go${go_version}.linux-${arch}.tar.gz" -o "$archive"
    printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status
    tar -xzf "$archive" -C "$workdir"
    export PATH="$workdir/go/bin:$PATH"
fi

git -c advice.detachedHead=false clone --depth 1 --branch "$tools_tag" \
    https://github.com/amnezia-vpn/amneziawg-tools.git "$workdir/tools"
git -c advice.detachedHead=false clone --depth 1 --branch "$runtime_tag" \
    https://github.com/amnezia-vpn/amneziawg-go.git "$workdir/runtime"
test "$(git -C "$workdir/tools" rev-parse HEAD)" = "$tools_revision"
test "$(git -C "$workdir/runtime" rev-parse HEAD)" = "$runtime_revision"

(
    cd "$workdir/runtime"
    CGO_ENABLED=0 make
)
(
    cd "$workdir/tools/src"
    make install DESTDIR="$destdir" PREFIX=/usr WITH_WGQUICK=yes \
        WITH_SYSTEMDUNITS=yes WITH_BASHCOMPLETION=no SYSTEMDUNITDIR=/usr/lib/systemd/system
)
install -m 0755 "$workdir/runtime/amneziawg-go" "$destdir/usr/bin/amneziawg-go"
