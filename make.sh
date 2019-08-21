#!/usr/bin/bash

RELEASE=${GOPATH}/release
VERSION=$(git tag | tail -n 1)

function check_err() {
    if [[ $? != 0 ]]
    then
        exit $?
    fi
}

pushd tools/sysmon && make -j 8 $@ || check_err && popd

pushd tools/whids && make -j 8 $@ || check_err && popd

pushd tools/manager && make -j 8 $@ || check_err && popd

pushd ${RELEASE}
# Remove previous bundles
rm *.tar.gz
tar -cvzf whids-${VERSION}-release-bundle.tar.gz *
popd


