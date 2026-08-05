#!/usr/bin/env sh
set -eu

install_prefix="${PREFIX:-${HOME}/.local}"

cargo build --release --locked
install -d "${install_prefix}/bin"
install -m 0755 target/release/mrk "${install_prefix}/bin/mrk"

printf 'Installed mrk to %s/bin\n' "${install_prefix}"
