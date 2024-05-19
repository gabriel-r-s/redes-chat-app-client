#!/bin/bash

echo "\$ cargo +nightly r -- $@"
cargo +nightly r -- $@
