#!/usr/bin/env bash

# To make sure aesmd service is started for aecs_server
if [ "$(basename $1)" == "aecs_server" ] ; then
    /usr/bin/start_aesm.sh
fi

# To start the service
export PATH=./:$PATH
"$@"
