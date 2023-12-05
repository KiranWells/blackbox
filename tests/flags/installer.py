#!/usr/bin/env python
import urllib.request
import os, stat

contents = urllib.request.urlopen("http://example.com/index.html")

with open("executable", "wb") as f:
    f.write(contents.read())

st = os.stat("executable")
os.chmod("executable", st.st_mode | stat.S_IEXEC)
os.execvp("./executable", ["./executable"]) 

