#!/usr/bin/bash

RELEASE=${GOPATH}/release
VERSION=$(git tag | tail -n 1)
TOOLS="utilities"

function check_err() {
    if [[ $? != 0 ]]
    then
        exit $?
    fi
}

pushd $TOOLS/sysmon && make -j 8 $@ || check_err && popd

pushd $TOOLS/whids && make -j 8 $@ || check_err && popd

pushd $TOOLS/manager && make -j 8 $@ || check_err && popd

pushd ${RELEASE}
# Remove previous bundles
rm *.zip
7z a -tzip whids-${VERSION}-release-bundle.zip *

popd


