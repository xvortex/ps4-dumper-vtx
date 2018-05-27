#!/bin/bash

set -e

pushd tool
make
popd

make

tool/bin2js ps4-dumper-vtx.bin > payload.js

sed "s/###/$(cat payload.js)/" exploit.template > exploit/index.html
