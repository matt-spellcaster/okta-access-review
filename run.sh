#!/bin/zsh
# Runs a live access review. Settings come from ./env; the private key is
# fetched from 1Password at startup and never written to disk.
# Any arguments are passed to access-review, e.g.:
#   ./run.sh --roster roster/dev-org-roster.csv --config roster/dev-org-config.json
set -e
DIR="${0:A:h}"
if [[ ! -r "$DIR/env" ]]; then
  echo "access-review: missing $DIR/env (copy env.example and fill it in)" >&2
  exit 1
fi
set -a; source "$DIR/env"; set +a
if [[ -z "$OKTA_PRIVATE_KEY_REF" ]]; then
  echo "access-review: OKTA_PRIVATE_KEY_REF is not set in $DIR/env" >&2
  exit 1
fi
if ! OKTA_PRIVATE_KEY="$(/opt/homebrew/bin/op read "$OKTA_PRIVATE_KEY_REF")"; then
  echo "access-review: could not read the key from 1Password ($OKTA_PRIVATE_KEY_REF)" >&2
  exit 1
fi
export OKTA_PRIVATE_KEY
unset OKTA_PRIVATE_KEY_REF
# Email is optional; only fetch the SMTP password when a recipient is set.
if [[ -n "$REPORT_EMAIL_TO" ]]; then
  if [[ -z "$SMTP_PASSWORD_REF" ]]; then
    echo "access-review: REPORT_EMAIL_TO is set but SMTP_PASSWORD_REF is not" >&2
    exit 1
  fi
  if ! SMTP_PASSWORD="$(/opt/homebrew/bin/op read "$SMTP_PASSWORD_REF")"; then
    echo "access-review: could not read the SMTP password from 1Password ($SMTP_PASSWORD_REF)" >&2
    exit 1
  fi
  export SMTP_PASSWORD
fi
unset SMTP_PASSWORD_REF
cd "$DIR"
exec /opt/homebrew/bin/uv run --frozen access-review "$@"
