#!/bin/bash

CYB3RHQ_DIR=/var/ossec
ENGINE_DIR=$CYB3RHQ_DIR/engine

OUTPUT_FILE_PATH=/tmp/engine.log

# cyb3rhq-engine configuration parameters
export WZE_LOG_LEVEL=error
export WZE_KVDB_PATH=$CYB3RHQ_DIR/etc/kvdb/
export WZE_STORE_PATH=$ENGINE_DIR/store/
export WZE_EVENT_SOCK=$CYB3RHQ_DIR/queue/sockets/queue
export WZE_API_SOCK=$CYB3RHQ_DIR/queue/sockets/engine-api
export WZE_FLOOD_FILE=/tmp/engine-flood.log
# TODO Temporary fix for the GeoIP database, this should be removed in the future
# when the database is downloaded by the manager
WZE_MMDB_CITY_PATH=$CYB3RHQ_DIR/etc/GeoLite2-City.mmdb
WZE_MMDB_ASN_PATH=$CYB3RHQ_DIR/etc/GeoLite2-ASN.mmdb
if [ -f $WZE_MMDB_CITY_PATH ]; then
    export WZE_MMDB_CITY_PATH
fi
if [ -f $WZE_MMDB_ASN_PATH ]; then
    export WZE_MMDB_ASN_PATH
fi

# Create flood file if it does not exist
if [ ! -e "$WZE_FLOOD_FILE" ]; then
    touch "$WZE_FLOOD_FILE"
fi

# TODO: improve the config testing section
if [ "$1" = "-t" ]; then
    exit 0
fi

# Configure code dump
ulimit -S -c unlimited
sysctl -w kernel.core_pattern=/coredumps/core-%e-%E-%t-%s-%p

# Clean sockets
rm -f $WZE_EVENT_SOCK
rm -f $WZE_API_SOCK

# Start Engine daemon
nohup $ENGINE_DIR/cyb3rhq-engine server start >>$OUTPUT_FILE_PATH 2>&1 &

# Control file for cyb3rhq-control, this file contains the cyb3rhq-engine pid
echo $! >$CYB3RHQ_DIR/var/run/cyb3rhq-engine-$!.pid

# Function to check if a file exists
check_file_existence() {
    local file=$1
    local max_retries=10
    local retries=0
    local sleep_interval=1

    while [[ ! -e $file && $retries -lt $max_retries ]]; do
        sleep $sleep_interval
        ((retries++))
    done

    if [[ ! -e $file ]]; then
        echo "Error: File $file does not exist after $max_retries retries."
        return 1
    fi

    return 0
}

# Files to check
files_to_check=("$WZE_EVENT_SOCK" "$WZE_API_SOCK")

# Check each file
for file in "${files_to_check[@]}"; do
    if ! check_file_existence "$file"; then
        exit 1
    fi
done

# Queues ownership setup
chown cyb3rhq:cyb3rhq $WZE_EVENT_SOCK
chown cyb3rhq:cyb3rhq $WZE_API_SOCK

echo "" >>/tmp/engine.log
