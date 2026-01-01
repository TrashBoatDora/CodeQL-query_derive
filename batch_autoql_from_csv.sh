#!/usr/bin/env bash
# Usage:
#   batch_autoql_from_csv.sh -c repos_python.csv -p ./projects [-a ./python_autoql.sh] [-l Python|"" for all] [-d 1] [-m N] [-S seconds]
# Example:
#   batch_autoql_from_csv.sh -c repos_python.csv -p ./projects -a ./python_autoql.sh -l Python -d 1 -S 2

set -u -o pipefail

CSV_FILE=""
PROJECTS_ROOT=""
AUTOQL_SCRIPT="./python_autoql.sh"
ONLY_LANGUAGE="Python"
GIT_DEPTH=1
MAX_COUNT=0
SLEEP_BETWEEN=0

print_help() { sed -n '2,22p' "$0"; }

while getopts ":c:p:a:l:d:m:S:h" opt; do
  case "$opt" in
    c) CSV_FILE="$OPTARG" ;;
    p) PROJECTS_ROOT="$OPTARG" ;;
    a) AUTOQL_SCRIPT="$OPTARG" ;;
    l) ONLY_LANGUAGE="$OPTARG" ;;
    d) GIT_DEPTH="$OPTARG" ;;
    m) MAX_COUNT="$OPTARG" ;;
    S) SLEEP_BETWEEN="$OPTARG" ;;
    h) print_help; exit 0 ;;
    \?) echo "Unknown option: -$OPTARG"; print_help; exit 1 ;;
    :)  echo "Option -$OPTARG requires an argument."; exit 1 ;;
  esac
done

# 基本檢查
if [[ -z "${CSV_FILE}" || -z "${PROJECTS_ROOT}" ]]; then
  echo "請至少指定 CSV (-c) 與 下載目錄 (-p)"; print_help; exit 1
fi
if [[ ! -f "$CSV_FILE" ]]; then
  echo "找不到 CSV 檔案：$CSV_FILE"; exit 1
fi
if [[ ! -x "$AUTOQL_SCRIPT" ]]; then
  echo "找不到或不可執行的 autoql 腳本：$AUTOQL_SCRIPT"; exit 1
fi

mkdir -p "$PROJECTS_ROOT"

COUNT=0
awk -v FPAT='([^,]*)|("[^"]*")' 'NR>1 {print $2 "\t" $4 "\t" $6}' "$CSV_FILE" | \
while IFS=$'\t' read -r full_name clone_url language; do
  full_name="${full_name%\"}"; full_name="${full_name#\"}"
  clone_url="${clone_url%\"}"; clone_url="${clone_url#\"}"
  language="${language%\"}"; language="${language#\"}"

  if [[ -n "$ONLY_LANGUAGE" && "$language" != "$ONLY_LANGUAGE" ]]; then
    continue
  fi

  COUNT=$((COUNT+1))
  if [[ "$MAX_COUNT" -gt 0 && "$COUNT" -gt "$MAX_COUNT" ]]; then
    break
  fi

  repo_slug="$full_name"
  repo_name="${repo_slug##*/}"
  dest="$PROJECTS_ROOT/$repo_name"
  venv_dir="$dest/.venv"
  venv_python="$venv_dir/bin/python"
  venv_pip="$venv_dir/bin/pip"

  echo "=== [$COUNT] $repo_slug ($language) ==="
  rm -rf "$dest"

  if ! git clone --depth "$GIT_DEPTH" "$clone_url" "$dest"; then
    echo "!! clone 失敗：$repo_slug"
    [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
    continue
  fi

  if ! find "$dest" -type f -name '*.py' -printf '.' -quit | grep -q .; then
    echo "-- 無 .py 檔，跳過：$repo_slug"
    rm -rf "$dest"
    [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
    continue
  fi

  if ! python3.12 -m venv "$venv_dir"; then
    echo "!! 建立 venv 失敗：$repo_slug"
    rm -rf "$dest"
    [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
    continue
  fi

  "$venv_pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true

  req_installed=false
  shopt -s nullglob
  for req in "$dest"/requirements.txt "$dest"/requirements-*.txt "$dest"/req*.txt; do
    if [[ -f "$req" ]]; then
      echo "-- 安裝依賴：$(basename "$req")"
      "$venv_pip" install -r "$req" || true
      req_installed=true
      break
    fi
  done
  shopt -u nullglob

  if [[ "$req_installed" = false ]]; then
    if [[ -f "$dest/pyproject.toml" || -f "$dest/setup.py" || -f "$dest/setup.cfg" ]]; then
      echo "-- 專案安裝（pip install .）"
      (cd "$dest" && "$venv_pip" install .) || true
    fi
  fi

  if PATH="$venv_dir/bin:$PATH" "$AUTOQL_SCRIPT" "$repo_name" "$dest"; then
    echo "-- autoql 完成：$repo_slug"
  else
    echo "!! autoql 失敗：$repo_slug"
  fi

  rm -rf "$dest"

  [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
done
