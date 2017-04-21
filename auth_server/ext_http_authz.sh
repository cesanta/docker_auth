#!/bin/sh

# post json to a url
# exit with 0 if request responds
# with 200 otherwise exit with 1
main() {
  read payload
  local url="$1"
  local status_code=$(curl -s -o /dev/null \
    -w "%{http_code}" \
    -X POST \
    -H "Content-Type:application/json" $url -d "$payload")
   if [ "$status_code" -eq "200" ]; then
     exit 0
   else
     exit 1
   fi
}

main "$@"
