#!/usr/bin/env bash

# Start aesmd if it is not running
if ! pgrep "aesm_service" > /dev/null ; then
    echo "Start aesmd service ..."
    LD_LIBRARY_PATH="/usr/local/lib:/opt/intel/sgxpsw/aesm:$LD_LIBRARY_PATH" \
        /opt/intel/sgxpsw/aesm/aesm_service
else
    echo "aesmd service is already started"
fi

sleep 5  # anyway, sleep a moment and then try to check
for ((i=0;i<5;i++)) ; do
    if [ -e /dev/isgx -a -e /var/opt/aesmd/data/white_list_cert.bin ] ; then
        break
    else
        echo "Wait $i/5 seconds for isgx and white list file"
        sleep 1
   fi
done
