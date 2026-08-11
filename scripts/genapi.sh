#!/usr/bin/env bash
set -e

export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.nvm/versions/node/$(ls $HOME/.nvm/versions/node/ | tail -1)/bin"

# Pastikan script selalu berjalan dari root direktori proyek
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

# Parse arguments
VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: ./genapi.sh [--version <semver>]"
            exit 1
            ;;
    esac
done

# Generate V1
INPUT_SPEC_V1="api/openapi/v1/openapi.yaml"
BUNDLED_SPEC_V1="api/openapi/v1/_bundled.yaml"
OUTPUT_DIR_V1="api/openapi/v1/generated"
mkdir -p "${OUTPUT_DIR_V1}"

# Update version jika flag --version diberikan
if [[ -n "${VERSION}" ]]; then
    echo "Updating version to ${VERSION}..."
    sed -i "s/^  version: .*/  version: ${VERSION}/" "${INPUT_SPEC_V1}"
fi

# Step 1: Bundle semua $ref menjadi satu file
echo "Bundling OpenAPI spec..."
npx -y @redocly/cli bundle "${INPUT_SPEC_V1}" -o "${BUNDLED_SPEC_V1}"

# Step 2: Generate code dari bundled spec
echo "Generating code..."
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest \
    -package apiv1 \
    -generate types,chi-server,spec \
    "${BUNDLED_SPEC_V1}" > "${OUTPUT_DIR_V1}/api.gen.go"

# Bundled file disimpan untuk di-serve oleh Swagger UI

echo "Berhasil generate OpenAPI V1!"
