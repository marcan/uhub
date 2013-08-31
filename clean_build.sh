#!/bin/bash

make clean
rm Makefile
find -iname '*cmake*' -not -name CMakeLists.txt -not -name 'cmake'  -not -name 'FindSqlite3.cmake' -exec rm -rf {} \+
