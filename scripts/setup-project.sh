#!/bin/bash
set -e

this_dir=$(dirname $0)

pushd "${this_dir}/../" >/dev/null

git submodule update --init --recursive

git update-index --assume-unchanged samples/basic-sample/config/app_config.h

popd >/dev/null
