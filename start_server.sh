#!/bin/bash

# Create .env.tmp file
# echo -e "ISSUER=${ISSUER}\nSECRET_KEY=${SECRET_KEY}\nCLIENT_ID=${CLIENT_ID}\nCLIENT_SECRET=${CLIENT_SECRET}" > .env.tmp

# Load variables
# (test -f .env || touch .env) ; if [[ $(diff .env .env.tmp | wc -l) -ne 0 ]] ; then echo "Importing new ENV variables" ; mv .env.tmp .env ; pub run build_runner clean ; pub run build_runner build --delete-conflicting-outputs ; fi
pub run build_runner clean ; pub run build_runner build --delete-conflicting-outputs 

# Start HTTP server
echo "Starting HTTP auth API server"
dart bin/auth.dart
