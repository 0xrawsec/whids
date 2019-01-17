#!/usr/bin/bash

pushd tools/whids; make -j 8 $@; popd
pushd tools/manager; make -j 8 $@; popd
