#!/usr/bin/env sh
# Host-side test runner for the HMA++ module. It needs only a C++17
# compiler and Python 3; it does not build the Android module and does not
# require the NDK. Run from anywhere:
#
#   sh tools/uid-seccomp-module/tests/run_tests.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULE=$(dirname "$HERE")
ROOT=$(CDPATH= cd -- "$MODULE/../.." && pwd)
BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT

CXX=${CXX:-c++}
status=0

echo "== Python checks =="
python3 "$HERE/test_version.py" || status=1
python3 "$HERE/test_release_tag.py" || status=1

echo
echo "== C++ filter tests =="
"$CXX" -std=c++17 -O1 -Wall -Wextra -Werror -I"$MODULE" -I"$HERE" \
    "$HERE/filter_test.cpp" -o "$BUILD/filter_test" || status=1
if [ -x "$BUILD/filter_test" ]; then
    "$BUILD/filter_test" || status=1
fi

echo
echo "== C++ module lifecycle tests =="
"$CXX" -std=c++17 -O1 -Wall -Wextra -rdynamic -I"$HERE/stubs" -I"$ROOT/third_party/zygisk" \
    -I"$MODULE" -I"$HERE" "$HERE/module_lifecycle_test.cpp" "$MODULE/module.cpp" \
    -o "$BUILD/module_lifecycle_test" -ldl || status=1
if [ -x "$BUILD/module_lifecycle_test" ]; then
    for scenario in clean no_backup chained commit_fail; do
        echo "-- scenario: $scenario"
        "$BUILD/module_lifecycle_test" "$scenario" || status=1
    done
fi

echo
if [ "$status" -eq 0 ]; then
    echo "ALL TESTS PASSED"
else
    echo "TESTS FAILED"
fi
exit "$status"
