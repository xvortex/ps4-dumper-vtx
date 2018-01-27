#!/bin/bash

set -e

pushd tool
make
popd

make

tool/bin2js ps4-dumper.bin > exploit/payload.js
