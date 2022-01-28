#/bin/bash

ROOT=`git rev-parse --show-toplevel`
cp hooks/* ${ROOT}/.git/hooks/