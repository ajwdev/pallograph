#!/bin/bash
set -eo pipefail

export PATH=/opt/ddlog/current/bin:$PATH

ddlog -L /opt/ddlog/current/lib -i pallograph.dl
(cd pallograph_ddlog && cargo build "$@")

exec pallograph_ddlog/target/debug/pallograph_cli < data.dat
