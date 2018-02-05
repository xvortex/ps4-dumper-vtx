#!/bin/bash

set -e

pushd tool
make
popd

make

tool/bin2js ps4-dumper.bin > exploit/payload.js
mv ps4-dumper.bin ps4-dumper-vtx.bin
