#!/usr/bin/env bash
# Ручной деплой с рабочей машины: push текущей ветки → SSH на сервер → pull + docker compose.
# Нужно задать DEPLOY_SSH_TARGET / DEPLOY_REMOTE_DIR.

set -euo pipefail

SSH_TARGET="${DEPLOY_SSH_TARGET:-user@your-server}"
REMOTE_DIR="${DEPLOY_REMOTE_DIR:-/opt/rusty-key-bot}"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"

echo "Pushing branch: ${BRANCH}"
git push -u origin "${BRANCH}"

echo "Deploying on ${SSH_TARGET}:${REMOTE_DIR} (branch ${BRANCH})"
# Heredoc на удалённой стороне: $1 = каталог репо, $2 = ветка (без подстановки локальных переменных).
ssh "${SSH_TARGET}" bash -s -- "${REMOTE_DIR}" "${BRANCH}" <<'EOF'
set -euo pipefail
REMOTE_DIR="$1"
BRANCH="$2"
cd "$REMOTE_DIR"

git fetch origin
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"

docker compose up -d --build --remove-orphans
docker compose ps
EOF
