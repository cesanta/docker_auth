#!/bin/bash
#
# Example external authenticator program for use with `ext_auth`.
#

read u p

if [ "$u" == "user" -a "$p" == "pass" ]; then
  exit 0
fi

if [ "$u" == "bofh" -a "$p" == "LART" ]; then
  echo '{"labels": {"level": ["max"], "groups": ["VIP", "ATeam"]}}'
  exit 0
fi

exit 1
