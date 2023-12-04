#!/bin/bash

set -ex

# change to root project directory
cd ..

# build the program
cargo xtask build-ebpf
cargo build --release

# run strace
strace -n -e quiet=exit -o strace_ls ls
# extract only system call IDs
cat strace_ls | awk 'sub(/]/, "", $2) { print $2 }' > strace_ids

# run blackbox
sudo ./target/release/blackbox --command "ls" --user $USER --include-initial-execve --file-to-write blackbox_ls.json
jq '.syscall_id' blackbox_ls.json > blackbox_ids

diff blackbox_ids strace_ids
if [[ $? != 0 ]]; then
  printf '\n\n\033[41m\033[90mIDs did not match!\033[0m\n\n\n'
else
  printf '\n\n\033[42m\033[90mTest passed!\033[0m\n\n\n'
fi

rm -f blackbox_ids blackbox_ls.json strace_ids strace_ls

set +ex
