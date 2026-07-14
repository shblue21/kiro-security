#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(node -p "require('${ROOT_DIR}/package.json').version")"
VSIX="${1:-${ROOT_DIR}/dist/kiro-security-power-${VERSION}.vsix}"
EXTENSION_ID="$(node -p "const p=require('${ROOT_DIR}/package.json'); p.publisher + '.' + p.name")"

find_kiro() {
  if [[ -n "${KIRO_CLI:-}" ]]; then
    printf '%s\n' "${KIRO_CLI}"
    return
  fi
  if command -v kiro >/dev/null 2>&1; then
    command -v kiro
    return
  fi
  local candidates=(
    "/Applications/Kiro.app/Contents/Resources/app/bin/kiro"
    "${HOME}/Applications/Kiro.app/Contents/Resources/app/bin/kiro"
    "/usr/local/bin/kiro"
    "/usr/bin/kiro"
    "/opt/kiro/bin/kiro"
    "/snap/bin/kiro"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done
  return 1
}

if [[ ! -f "${VSIX}" ]]; then
  echo "VSIX not found: ${VSIX}" >&2
  echo "Run 'npm ci && npm run package' first, or pass an explicit VSIX path." >&2
  exit 2
fi

if ! KIRO_BIN="$(find_kiro)"; then
  cat >&2 <<'MSG'
Kiro CLI was not found. Discovery order was:
  1. KIRO_CLI
  2. kiro on PATH
  3. macOS Kiro.app bundle
  4. common Linux installation paths
Set KIRO_CLI to the executable and rerun this script.
MSG
  exit 3
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kiro-security-power-verify.XXXXXX")"
USER_DATA_DIR="${WORK_DIR}/user-data"
EXTENSIONS_DIR="${WORK_DIR}/extensions"
WORKSPACE_DIR="${WORK_DIR}/fixture-workspace"
RESULT_FILE="${WORK_DIR}/local-verification-result.json"
mkdir -p "${USER_DATA_DIR}" "${EXTENSIONS_DIR}" "${WORKSPACE_DIR}"
cp -R "${ROOT_DIR}/fixtures/vulnerable-repo/." "${WORKSPACE_DIR}/"
rm -rf "${WORKSPACE_DIR}/.git" "${WORKSPACE_DIR}/.kiro"
if command -v git >/dev/null 2>&1; then
  git -C "${WORKSPACE_DIR}" init -q
  git -C "${WORKSPACE_DIR}" config user.email "kiro-security-verification@example.invalid"
  git -C "${WORKSPACE_DIR}" config user.name "Kiro Security Verification"
  git -C "${WORKSPACE_DIR}" add .
  git -C "${WORKSPACE_DIR}" commit -qm "verification fixture"
fi

COMMON_ARGS=(--user-data-dir "${USER_DATA_DIR}" --extensions-dir "${EXTENSIONS_DIR}")
echo "Using Kiro CLI: ${KIRO_BIN}"
echo "Using isolated profile: ${WORK_DIR}"
"${KIRO_BIN}" "${COMMON_ARGS[@]}" --install-extension "${VSIX}" --force

INSTALLED="$(${KIRO_BIN} "${COMMON_ARGS[@]}" --list-extensions --show-versions || true)"
if ! grep -Fqi "${EXTENSION_ID}" <<<"${INSTALLED}"; then
  echo "Kiro did not report ${EXTENSION_ID} as installed." >&2
  echo "Installed extensions:" >&2
  echo "${INSTALLED}" >&2
  exit 4
fi

echo "VSIX installation was reported by Kiro. Launching the isolated fixture workspace."
cat > "${RESULT_FILE}" <<JSON
{
  "schemaVersion": "1.0",
  "productVersion": "${VERSION}",
  "vsixPath": "${VSIX}",
  "kiroExecutable": "${KIRO_BIN}",
  "testedAt": null,
  "platform": "$(uname -s 2>/dev/null || echo unknown)",
  "checks": {
    "installed": true,
    "activityBarIcon": null,
    "secondarySideBar": null,
    "standardScan": null,
    "liveProgress": null,
    "realFinding": null,
    "sourceNavigation": null,
    "problemsDiagnostic": null,
    "exports": null,
    "historyAfterRestart": null,
    "resumeInterruptedScan": null,
    "mcpToVsix": null,
    "vsixToMcp": null,
    "disableAndUninstall": null
  },
  "notes": []
}
JSON

cat <<MSG

Complete the interactive checklist in:
  ${ROOT_DIR}/docs/local-kiro-smoke-test.md

Record results in:
  ${RESULT_FILE}
Validate the file against:
  ${ROOT_DIR}/docs/local-verification-result.schema.json

The script verified installation only. It does not claim the Kiro UI checks passed.
MSG

"${KIRO_BIN}" "${COMMON_ARGS[@]}" --new-window "${WORKSPACE_DIR}"
