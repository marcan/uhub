#!/bin/bash

make clean
rm Makefile
find -iname '*cmake*' -not -name CMakeLists.txt -not -path "./cmake" -not -path "./cmake/*" -exec rm -rf {} \+
