#!/bin/bash

# This script is the Docker container entry point.



# In Dockerfile do this:
#   install docker/authmatter-docker-entry.sh -m755 /usr/local/bin/authmatter-docker-entry.sh


export AM_CONFIG_PATH=/config.json
export AM_SQLITE_PATH=/db.sqlite
export PORT=8080

node /root/authmatter-node/src/am-server.js
