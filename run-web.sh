#!/usr/bin/env bash

set -e

TRACE=false
BRANCH=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --trace)  TRACE=true; shift ;;
    --branch) BRANCH="$2"; shift 2 ;;
    *) echo "Usage: $0 [--trace] [--branch <name>]"; exit 1 ;;
  esac
done

export Logging__LogLevel__Default=Information
export Logging__LogLevel__Microsoft__AspNetCore=Warning
export Logging__LogLevel__Program=Debug
export Logging__LogLevel__Ednsv__Web=Debug

if $TRACE; then
  export MaskTrace=False
else
  export MaskTrace=True
fi

git pull

if [[ -n "$BRANCH" ]]; then
  git switch "$BRANCH"
  git pull
fi

dotnet run --project src/Ednsv.Web
