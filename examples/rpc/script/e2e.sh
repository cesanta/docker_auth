#!/bin/sh -eu

SUBJECT_HOST="127.0.0.1:5001"
if test $# -gt 0; then
  SUBJECT_HOST="${1}"
fi

TEST_VALID_USERNAME="admin@localhost"
TEST_VALID_PASSWORD="admin"
TEST_INVALID_USERNAME="admin@localhost"
TEST_INVALID_PASSWORD="password"
TEST_FAIL_AUTHN_USERNAME="admin@authn.error"
TEST_FAIL_AUTHN_PASSWORD="admin"
TEST_FAIL_AUTHZ_USERNAME="admin@authz.error"
TEST_FAIL_AUTHZ_PASSWORD="admin"
TEST_VALID_SCOPE="repository:user-images/localhost/admin:pull"
TEST_INVALID_SCOPE="repository:example/admin/my-app:pull"

STATUS_CODE=$(curl -o /dev/null -w '%{http_code}' -u "${TEST_INVALID_USERNAME}:${TEST_INVALID_PASSWORD}" -s "http://${SUBJECT_HOST}/auth/token?scope=${TEST_VALID_SCOPE}")
if test "$STATUS_CODE" != "401"; then
  echo "expected status code 401, got ${STATUS_CODE}" >&2
  exit 1
fi

# the example plugin expects the password to match the user part of the username email address
STATUS_CODE=$(curl -o /dev/null -w '%{http_code}' -u "${TEST_VALID_USERNAME}:${TEST_VALID_PASSWORD}" -s "http://${SUBJECT_HOST}/auth/token?scope=${TEST_VALID_SCOPE}")
if test "$STATUS_CODE" != "200"; then
  echo "expected status code 200, got ${STATUS_CODE}" >&2
  exit 1
fi

# still passes but the JWT does not contain access instructions for the requested scope
STATUS_CODE=$(curl -o /dev/null -w '%{http_code}' -u "${TEST_VALID_USERNAME}:${TEST_VALID_PASSWORD}" -s "http://${SUBJECT_HOST}/auth/token?scope=${TEST_INVALID_SCOPE}")
if test "$STATUS_CODE" != "200"; then
  echo "expected status code 200, got ${STATUS_CODE}" >&2
  exit 1
fi

# trigger simulated authentication error
STATUS_CODE=$(curl -o /dev/null -w '%{http_code}' -u "${TEST_FAIL_AUTHN_USERNAME}:${TEST_FAIL_AUTHN_PASSWORD}" -s "http://${SUBJECT_HOST}/auth/token?scope=${TEST_VALID_SCOPE}")
if test "$STATUS_CODE" != "500"; then
  echo "expected status code 500, got ${STATUS_CODE}" >&2
  exit 1
fi

# trigger simulated authorization error
STATUS_CODE=$(curl -o /dev/null -w '%{http_code}' -u "${TEST_FAIL_AUTHZ_USERNAME}:${TEST_FAIL_AUTHZ_PASSWORD}" -s "http://${SUBJECT_HOST}/auth/token?scope=${TEST_VALID_SCOPE}")
if test "$STATUS_CODE" != "500"; then
  echo "expected status code 500, got ${STATUS_CODE}" >&2
  exit 1
fi

:
