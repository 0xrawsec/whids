#!/bin/bash
set -e

pkgs=("./logger" "./api")

tmp=$(mktemp -d)
coverprofile="${tmp}/coverage.out"
coverage_dir=".github/coverage"
out="${coverage_dir}/coverage.txt"

mkdir -p "${coverage_dir}"

GOOS=linux go test -short -failfast -v -coverprofile="${coverprofile}" ${pkgs[*]}
go tool cover -func "${coverprofile}" | tee "${out}"