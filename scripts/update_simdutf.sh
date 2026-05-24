#!/bin/bash
set -ex
cd "$(dirname "$0")"
rm -rf simdutf
LATEST_VERSION=$(curl -s https://api.github.com/repos/simdutf/simdutf/releases/latest | grep '"tag_name"' | cut -d '"' -f 4)
mkdir simdutf
curl -L https://github.com/simdutf/simdutf/archive/refs/tags/${LATEST_VERSION}.tar.gz | tar -xzf - --strip-components=1 -C simdutf
python3 simdutf/singleheader/amalgamate.py --no-zip --no-readme --with-utf8 --with-base64 --with-latin1
cp simdutf/singleheader/simdutf.{cpp,h} ../src
rm -rf simdutf
