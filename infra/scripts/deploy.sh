#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/var/www/devopsec"

cd "$APP_DIR"
git pull origin main

cd backend
npm ci
npm run build
pm2 startOrRestart "$APP_DIR/infra/pm2/ecosystem.config.js"

cd "$APP_DIR/frontend"
npm ci
npm run build

sudo systemctl reload nginx
