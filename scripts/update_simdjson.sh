#!/bin/bash
set -ex
DIRNAME=$(dirname "$0")
LATEST_VERSION=$(curl -s -f https://api.github.com/repos/simdjson/simdjson/releases/latest | grep '"tag_name"' | cut -d '"' -f 4)
TEMP_DIR=$(mktemp -d -t simdjson)
curl -L -f https://github.com/simdjson/simdjson/archive/refs/tags/${LATEST_VERSION}.tar.gz | tar -xzf - --strip-components=1 -C $TEMP_DIR
patch $TEMP_DIR/include/simdjson/generic/numberparsing.h $DIRNAME/numberparsing.h.patch
python3 $TEMP_DIR/singleheader/amalgamate.py
cp $TEMP_DIR/singleheader/simdjson.{cpp,h} $DIRNAME/../src
rm -rf $TEMP_DIR
