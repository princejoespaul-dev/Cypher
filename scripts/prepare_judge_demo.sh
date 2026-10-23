#!/usr/bin/env bash
set -euo pipefail

# Build both real local images, pin their immutable image IDs in the existing API,
# and expose only loopback-bound ports. Requires a running local CYPHER API.
API_BASE="${CYPHER_API_BASE:-http://127.0.0.1:8000}"
API_KEY="${CYPHER_API_KEY:-dev-only-change-me}"
VULN_IMAGE="cypher-judge-demo:vulnerable"
FIXED_IMAGE="cypher-judge-demo:fixed"
VULN_CONTAINER="cypher-judge-demo-vulnerable"
FIXED_CONTAINER="cypher-judge-demo-fixed"
VULN_PORT=18081
FIXED_PORT=18082

command -v docker >/dev/null || { echo "Docker is required." >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required." >&2; exit 1; }
command -v git >/dev/null || { echo "Run this from a Git checkout." >&2; exit 1; }
curl -fsS "$API_BASE/healthz" >/dev/null || { echo "Start CYPHER first (make up)." >&2; exit 1; }

GIT_REF="$(git rev-parse HEAD)"
docker build -f Dockerfile.judge-demo --build-arg DEMO_FIXED=false -t "$VULN_IMAGE" .
docker build -f Dockerfile.judge-demo --build-arg DEMO_FIXED=true -t "$FIXED_IMAGE" .
VULN_DIGEST="$(docker image inspect "$VULN_IMAGE" --format '{{.Id}}' | sed 's/^sha256:/sha256:/')"
FIXED_DIGEST="$(docker image inspect "$FIXED_IMAGE" --format '{{.Id}}' | sed 's/^sha256:/sha256:/')"

# Demo containers are explicitly loopback-only; remove only containers with these demo names.
docker rm -f "$VULN_CONTAINER" "$FIXED_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$VULN_CONTAINER" --restart unless-stopped -p "127.0.0.1:$VULN_PORT:8001" "$VULN_IMAGE" >/dev/null
docker run -d --name "$FIXED_CONTAINER" --restart unless-stopped -p "127.0.0.1:$FIXED_PORT:8001" "$FIXED_IMAGE" >/dev/null

# Wait briefly for both local targets before registering their metadata.
for port in "$VULN_PORT" "$FIXED_PORT"; do
  ready=0
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$port/openapi.json" >/dev/null; then ready=1; break; fi
    sleep 1
  done
  [ "$ready" = 1 ] || { echo "Judge target on port $port did not become ready." >&2; exit 1; }
done

AUTH=(-H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json')
TARGETS="$(curl -fsS "${AUTH[@]}" "$API_BASE/v1/targets")"
TARGET_ID="$(python -c 'import json,sys; a=json.load(sys.stdin); print(next((x["target_id"] for x in a if x["name"]=="AuthTrace Judge Demo"), ""))' <<<"$TARGETS")"
if [ -z "$TARGET_ID" ]; then
  TARGET="$(curl -fsS -X POST "${AUTH[@]}" "$API_BASE/v1/targets" -d "{\"name\":\"AuthTrace Judge Demo\",\"base_url\":\"http://127.0.0.1:$VULN_PORT\",\"host_allowlist\":[\"127.0.0.1\"],\"openapi_spec_ref\":\"judge-demo-openapi-v1\"}")"
  TARGET_ID="$(python -c 'import json,sys; print(json.load(sys.stdin)["target_id"])' <<<"$TARGET")"
fi

BUILDS="$(curl -fsS "${AUTH[@]}" "$API_BASE/v1/targets/$TARGET_ID/builds")"
for spec in "vulnerable|judge-vulnerable-v1|$VULN_DIGEST" "fixed|judge-fixed-v1|$FIXED_DIGEST"; do
  IFS='|' read -r label ref digest <<<"$spec"
  if ! python -c 'import json,sys; a=json.load(sys.stdin); sys.exit(0 if any(x["label"]==sys.argv[1] for x in a) else 1)' "$label" <<<"$BUILDS"; then
    curl -fsS -X POST "${AUTH[@]}" "$API_BASE/v1/targets/$TARGET_ID/builds" -d "{\"label\":\"$label\",\"git_ref\":\"$GIT_REF\",\"image_digest\":\"$digest\"}" >/dev/null
  fi
done

echo "Judge demo prepared."
echo "Vulnerable target: http://127.0.0.1:$VULN_PORT (image ID $VULN_DIGEST)"
echo "Fixed target:      http://127.0.0.1:$FIXED_PORT (image ID $FIXED_DIGEST)"
echo "Registered target/build metadata at $API_BASE. Open the dashboard and choose Run Judge Demo."
