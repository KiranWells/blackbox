#!/bin/bash

set -ex

# change to root project directory
cd ..

# build the program
cargo xtask build-ebpf
cargo build --release

profile ()
{
  COMMAND=$1

  # run command on its own
  time $COMMAND

  # run strace
  time strace -o /dev/null $COMMAND

  # run blackbox
  time sudo ./target/release/blackbox --command "$COMMAND" --user $USER --file-to-write /dev/null
}

profile "du -sh ."
profile "dd if=/dev/random of=/dev/null count=2000"

set +ex
