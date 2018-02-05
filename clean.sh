#!/bin/bash

pushd tool
make clean
popd

make clean

rm -f *.bin
