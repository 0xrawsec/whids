#!/bin/bash
set -e

./coverage.sh

GOOS=linux go run tools/manager/*.go -openapi > ./doc/admin.openapi.json
