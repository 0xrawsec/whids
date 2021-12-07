#!/bin/bash
set -e

pkgs=("./logger" "./api" "./event")

tmp=$(mktemp -d)
coverprofile="${tmp}/coverage.out"
coverage_dir=".github/coverage"
out="${coverage_dir}/coverage.txt"

mkdir -p "${coverage_dir}"

GOOS=linux go test -short -failfast -v -coverprofile="${coverprofile}" ${pkgs[*]}
go tool cover -func "${coverprofile}" | tee "${out}"

url_message=`cat ${out} | tail -n -1 | awk -F"\t" '{print $NF}' | tr -d '[:cntrl:]' | sed 's/%/%25/'`
curl -s https://img.shields.io/badge/coverage-${url_message}-informational > ${coverage_dir}/badge.svg
