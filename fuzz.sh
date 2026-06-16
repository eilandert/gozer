#!/usr/bin/env bash
# Local long-running fuzzing for gozer.
#
# CI runs only a ~30s smoke per target (see .github/workflows/ci.yml). This
# script is for deeper, LOCAL fuzzing — run it before a release or after
# touching the HTTP/request or config-parsing code. Any crasher it finds is
# written to internal/gozer/testdata/fuzz/<Target>/ ; commit that file as a
# regression seed.
#
# Usage:
#   ./fuzz.sh            # 10 minutes per target
#   ./fuzz.sh 1h         # 1 hour per target
#   ./fuzz.sh 30s FuzzServe   # custom time, single target
set -euo pipefail
cd "$(dirname "$0")"

TIME="${1:-10m}"
shift || true
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=(FuzzServe FuzzParsePyzorServers)
fi

for fn in "${TARGETS[@]}"; do
  echo "== fuzzing $fn for $TIME =="
  go test -mod=vendor -run=x -fuzz="^${fn}\$" -fuzztime="$TIME" ./internal/gozer/
done
echo "== done =="
