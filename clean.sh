#!/bin/bash

pushd tool
make clean
popd

make clean

rm -f ps4-dumper-vtx.bin payload.js
