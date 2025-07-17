#!/bin/bash

export CARGO_BUILD_TARGET="$(arch)-unknown-linux-gnu"
cargo build "$@"
