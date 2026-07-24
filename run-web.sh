#!/usr/bin/env bash

set -e

TRACE=false
NO_MASK=false
BRANCH=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --trace)   TRACE=true; shift ;;
    --no-mask) NO_MASK=true; shift ;;
    --branch)  BRANCH="$2"; shift 2 ;;
    *) echo "Usage: $0 [--trace [--no-mask]] [--branch <name>]"; exit 1 ;;
  esac
done

export Logging__LogLevel__Default=Information
export Logging__LogLevel__Microsoft__AspNetCore=Warning

if $TRACE; then
  export Trace=True
  export Logging__LogLevel__Program=Debug
  export Logging__LogLevel__Ednsv__Web=Debug
  if $NO_MASK; then
    export MaskTrace=False
  else
    export MaskTrace=True
  fi
fi

salt="$( cat ../../Keys/trace-mask-salt.txt )"
if [[ "$salt" == "" ]]; then
	echo "Salt missing.">&2
	return 1
fi


export EDNSV_AUTH_TOKEN_HASH="$( cat ../../Keys/ednsv-root-hash.txt )"
export MaskSalt="$salt"

git pull

if [[ -n "$BRANCH" ]]; then
  git switch "$BRANCH"
  git pull
fi

export Logging__Console__FormatterName=Simple

dotnet run --no-restore --project src/Ednsv.Web

if [[ "$?" != "130" ]]; then
	echo "Trying with restore allowed."
	dotnet run --project src/Ednsv.Web
fi