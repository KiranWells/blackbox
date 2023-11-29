#!/usr/bin/env python
import os

files = ["~/.bash_history", "~/.zsh_history", "~/.aws/credentials", "/etc/passwd"]

for file in files:
    try:
        with open(os.path.expanduser(file)) as f:
            print(f.read())
    except:
        print(f"failed to read {file}")


