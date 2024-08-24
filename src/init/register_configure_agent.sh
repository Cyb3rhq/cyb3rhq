#!/bin/bash

# Copyright (C) 2015, Cyb3rhq Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Global variables
INSTALLDIR=${1}
CONF_FILE="${INSTALLDIR}/etc/ossec.conf"
TMP_ENROLLMENT="${INSTALLDIR}/tmp/enrollment-configuration"
TMP_SERVER="${INSTALLDIR}/tmp/server-configuration"
CYB3RHQ_REGISTRATION_PASSWORD_PATH="etc/authd.pass"
CYB3RHQ_MACOS_AGENT_DEPLOYMENT_VARS="/tmp/cyb3rhq_envs"


# Set default sed alias
sed="sed -ri"
# By default, use gnu sed (gsed).
use_unix_sed="False"

# Special function to use generic sed
unix_sed() {

    sed_expression="$1"
    target_file="$2"
    special_args="$3"

    sed ${special_args} "${sed_expression}" "${target_file}" > "${target_file}.tmp"
    cat "${target_file}.tmp" > "${target_file}"
    rm "${target_file}.tmp"

}

# Update the value of a XML tag inside the ossec.conf
edit_value_tag() {

    file=""

    if [ -z "$3" ]; then
        file="${CONF_FILE}"
    else
        file="${TMP_ENROLLMENT}"
    fi

    if [ -n "$1" ] && [ -n "$2" ]; then
        start_config="$(grep -n "<$1>" "${file}" | cut -d':' -f 1)"
        end_config="$(grep -n "</$1>" "${file}" | cut -d':' -f 1)"
        if [ -z "${start_config}" ] && [ -z "${end_config}" ] && [ "${file}" = "${TMP_ENROLLMENT}" ]; then
            echo "      <$1>$2</$1>" >> "${file}"
        elif [ "${use_unix_sed}" = "False" ] ; then
            ${sed} "s#<$1>.*</$1>#<$1>$2</$1>#g" "${file}"
        else
            unix_sed "s#<$1>.*</$1>#<$1>$2</$1>#g" "${file}"
        fi
    fi
    
    if [ "$?" != "0" ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') agent-auth: Error updating $2 with variable $1." >> "${INSTALLDIR}/logs/ossec.log"
    fi

}

delete_blank_lines() {

    file=$1
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} '/^$/d' "${file}"
    else
        unix_sed '/^$/d' "${file}"
    fi

}

delete_auto_enrollment_tag() {

    # Delete the configuration tag if its value is empty
    # This will allow using the default value
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"
    else
        unix_sed "s#.*<$1>.*</$1>.*##g" "${TMP_ENROLLMENT}"
    fi

    cat -s "${TMP_ENROLLMENT}" > "${TMP_ENROLLMENT}.tmp"
    mv "${TMP_ENROLLMENT}.tmp" "${TMP_ENROLLMENT}"

}

# Change address block of the ossec.conf
add_adress_block() {

    # Remove the server configuration
    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<server>/,/\/server>/d" "${CONF_FILE}"
    else
        unix_sed "/<server>/,/\/server>/d" "${CONF_FILE}"
    fi

    # Write the client configuration block
    for i in "${!ADDRESSES[@]}";
    do
        {
            echo "    <server>"
            echo "      <address>${ADDRESSES[i]}</address>"
            echo "      <port>1514</port>"
            if [ -n "${PROTOCOLS[i]}" ]; then
                echo "      <protocol>${PROTOCOLS[i]}</protocol>"
            else
                echo "      <protocol>tcp</protocol>"
            fi 
            echo "    </server>"
        } >> "${TMP_SERVER}"
    done

    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<client>/r ${TMP_SERVER}" "${CONF_FILE}"
    else
        unix_sed "/<client>/r ${TMP_SERVER}" "${CONF_FILE}"
    fi

    rm -f "${TMP_SERVER}"

}

add_parameter () {

    if [ -n "$3" ]; then
        OPTIONS="$1 $2 $3"
    fi
    echo "${OPTIONS}"

}

get_deprecated_vars () {

    if [ -n "${CYB3RHQ_MANAGER_IP}" ] && [ -z "${CYB3RHQ_MANAGER}" ]; then
        CYB3RHQ_MANAGER=${CYB3RHQ_MANAGER_IP}
    fi
    if [ -n "${CYB3RHQ_AUTHD_SERVER}" ] && [ -z "${CYB3RHQ_REGISTRATION_SERVER}" ]; then
        CYB3RHQ_REGISTRATION_SERVER=${CYB3RHQ_AUTHD_SERVER}
    fi
    if [ -n "${CYB3RHQ_AUTHD_PORT}" ] && [ -z "${CYB3RHQ_REGISTRATION_PORT}" ]; then
        CYB3RHQ_REGISTRATION_PORT=${CYB3RHQ_AUTHD_PORT}
    fi
    if [ -n "${CYB3RHQ_PASSWORD}" ] && [ -z "${CYB3RHQ_REGISTRATION_PASSWORD}" ]; then
        CYB3RHQ_REGISTRATION_PASSWORD=${CYB3RHQ_PASSWORD}
    fi
    if [ -n "${CYB3RHQ_NOTIFY_TIME}" ] && [ -z "${CYB3RHQ_KEEP_ALIVE_INTERVAL}" ]; then
        CYB3RHQ_KEEP_ALIVE_INTERVAL=${CYB3RHQ_NOTIFY_TIME}
    fi
    if [ -n "${CYB3RHQ_CERTIFICATE}" ] && [ -z "${CYB3RHQ_REGISTRATION_CA}" ]; then
        CYB3RHQ_REGISTRATION_CA=${CYB3RHQ_CERTIFICATE}
    fi
    if [ -n "${CYB3RHQ_PEM}" ] && [ -z "${CYB3RHQ_REGISTRATION_CERTIFICATE}" ]; then
        CYB3RHQ_REGISTRATION_CERTIFICATE=${CYB3RHQ_PEM}
    fi
    if [ -n "${CYB3RHQ_KEY}" ] && [ -z "${CYB3RHQ_REGISTRATION_KEY}" ]; then
        CYB3RHQ_REGISTRATION_KEY=${CYB3RHQ_KEY}
    fi
    if [ -n "${CYB3RHQ_GROUP}" ] && [ -z "${CYB3RHQ_AGENT_GROUP}" ]; then
        CYB3RHQ_AGENT_GROUP=${CYB3RHQ_GROUP}
    fi

}

set_vars () {

    export CYB3RHQ_MANAGER
    export CYB3RHQ_MANAGER_PORT
    export CYB3RHQ_PROTOCOL
    export CYB3RHQ_REGISTRATION_SERVER
    export CYB3RHQ_REGISTRATION_PORT
    export CYB3RHQ_REGISTRATION_PASSWORD
    export CYB3RHQ_KEEP_ALIVE_INTERVAL
    export CYB3RHQ_TIME_RECONNECT
    export CYB3RHQ_REGISTRATION_CA
    export CYB3RHQ_REGISTRATION_CERTIFICATE
    export CYB3RHQ_REGISTRATION_KEY
    export CYB3RHQ_AGENT_NAME
    export CYB3RHQ_AGENT_GROUP
    export ENROLLMENT_DELAY
    # The following variables are yet supported but all of them are deprecated
    export CYB3RHQ_MANAGER_IP
    export CYB3RHQ_NOTIFY_TIME
    export CYB3RHQ_AUTHD_SERVER
    export CYB3RHQ_AUTHD_PORT
    export CYB3RHQ_PASSWORD
    export CYB3RHQ_GROUP
    export CYB3RHQ_CERTIFICATE
    export CYB3RHQ_KEY
    export CYB3RHQ_PEM

    if [ -r "${CYB3RHQ_MACOS_AGENT_DEPLOYMENT_VARS}" ]; then
        . ${CYB3RHQ_MACOS_AGENT_DEPLOYMENT_VARS}
        rm -rf "${CYB3RHQ_MACOS_AGENT_DEPLOYMENT_VARS}"
    fi

}

unset_vars() {

    vars=(CYB3RHQ_MANAGER_IP CYB3RHQ_PROTOCOL CYB3RHQ_MANAGER_PORT CYB3RHQ_NOTIFY_TIME \
          CYB3RHQ_TIME_RECONNECT CYB3RHQ_AUTHD_SERVER CYB3RHQ_AUTHD_PORT CYB3RHQ_PASSWORD \
          CYB3RHQ_AGENT_NAME CYB3RHQ_GROUP CYB3RHQ_CERTIFICATE CYB3RHQ_KEY CYB3RHQ_PEM \
          CYB3RHQ_MANAGER CYB3RHQ_REGISTRATION_SERVER CYB3RHQ_REGISTRATION_PORT \
          CYB3RHQ_REGISTRATION_PASSWORD CYB3RHQ_KEEP_ALIVE_INTERVAL CYB3RHQ_REGISTRATION_CA \
          CYB3RHQ_REGISTRATION_CERTIFICATE CYB3RHQ_REGISTRATION_KEY CYB3RHQ_AGENT_GROUP \
          ENROLLMENT_DELAY)

    for var in "${vars[@]}"; do
        unset "${var}"
    done

}

# Function to convert strings to lower version
tolower () {

    echo "$1" | tr '[:upper:]' '[:lower:]'

}


# Add auto-enrollment configuration block
add_auto_enrollment () {

    start_config="$(grep -n "<enrollment>" "${CONF_FILE}" | cut -d':' -f 1)"
    end_config="$(grep -n "</enrollment>" "${CONF_FILE}" | cut -d':' -f 1)"
    if [ -n "${start_config}" ] && [ -n "${end_config}" ]; then
        start_config=$(( start_config + 1 ))
        end_config=$(( end_config - 1 ))
        sed -n "${start_config},${end_config}p" "${INSTALLDIR}/etc/ossec.conf" >> "${TMP_ENROLLMENT}"
    else
        # Write the client configuration block
        {
            echo "    <enrollment>"
            echo "      <enabled>yes</enabled>"
            echo "      <manager_address>MANAGER_IP</manager_address>"
            echo "      <port>1515</port>"
            echo "      <agent_name>agent</agent_name>"
            echo "      <groups>Group1</groups>"
            echo "      <server_ca_path>/path/to/server_ca</server_ca_path>"
            echo "      <agent_certificate_path>/path/to/agent.cert</agent_certificate_path>"
            echo "      <agent_key_path>/path/to/agent.key</agent_key_path>"
            echo "      <authorization_pass_path>/path/to/authd.pass</authorization_pass_path>"
            echo "      <delay_after_enrollment>20</delay_after_enrollment>"
            echo "    </enrollment>" 
        } >> "${TMP_ENROLLMENT}"
    fi

}

# Add the auto_enrollment block to the configuration file
concat_conf() {

    if [ "${use_unix_sed}" = "False" ] ; then
        ${sed} "/<\/crypto_method>/r ${TMP_ENROLLMENT}" "${CONF_FILE}"
    else
        unix_sed "/<\/crypto_method>/r ${TMP_ENROLLMENT}/" "${CONF_FILE}"
    fi

    rm -f "${TMP_ENROLLMENT}"

}

# Set autoenrollment configuration
set_auto_enrollment_tag_value () {

    tag="$1"
    value="$2"

    if [ -n "${value}" ]; then
        edit_value_tag "${tag}" "${value}" "auto_enrollment"
    else
        delete_auto_enrollment_tag "${tag}" "auto_enrollment"
    fi

}

# Main function the script begin here
main () {

    uname_s=$(uname -s)

    # Check what kind of system we are working with
    if [ "${uname_s}" = "Darwin" ]; then
        sed="sed -ire"
        set_vars
    elif [ "${uname_s}" = "AIX" ] || [ "${uname_s}" = "SunOS" ] || [ "${uname_s}" = "HP-UX" ]; then
        use_unix_sed="True"
    fi

    get_deprecated_vars

    if [ -z "${CYB3RHQ_MANAGER}" ] && [ -n "${CYB3RHQ_PROTOCOL}" ]; then
        PROTOCOLS=( $(tolower "${CYB3RHQ_PROTOCOL//,/ }") )
        edit_value_tag "protocol" "${PROTOCOLS[0]}"
    fi

    if [ -n "${CYB3RHQ_MANAGER}" ]; then
        if [ ! -f "${INSTALLDIR}/logs/ossec.log" ]; then
            touch -f "${INSTALLDIR}/logs/ossec.log"
            chmod 660 "${INSTALLDIR}/logs/ossec.log"
            chown root:cyb3rhq "${INSTALLDIR}/logs/ossec.log"
        fi

        # Check if multiples IPs are defined in variable CYB3RHQ_MANAGER
        ADDRESSES=( ${CYB3RHQ_MANAGER//,/ } ) 
        PROTOCOLS=( $(tolower "${CYB3RHQ_PROTOCOL//,/ }") )
        # Get uniques values if all protocols are the same
        if ( [ "${#PROTOCOLS[@]}" -ge "${#ADDRESSES[@]}" ] && ( ( ! echo "${PROTOCOLS[@]}" | grep -q -w "tcp" ) || ( ! echo "${PROTOCOLS[@]}" | grep -q -w "udp" ) ) ) || [ ${#PROTOCOLS[@]} -eq 0 ] || ( ! echo "${PROTOCOLS[@]}" | grep -q -w "udp" ) ; then
            ADDRESSES=( $(echo "${ADDRESSES[@]}" |  tr ' ' '\n' | cat -n | sort -uk2 | sort -n | cut -f2- | tr '\n' ' ') ) 
        fi
        
        add_adress_block
    fi

    edit_value_tag "port" "${CYB3RHQ_MANAGER_PORT}"

    if [ -n "${CYB3RHQ_REGISTRATION_SERVER}" ] || [ -n "${CYB3RHQ_REGISTRATION_PORT}" ] || [ -n "${CYB3RHQ_REGISTRATION_CA}" ] || [ -n "${CYB3RHQ_REGISTRATION_CERTIFICATE}" ] || [ -n "${CYB3RHQ_REGISTRATION_KEY}" ] || [ -n "${CYB3RHQ_AGENT_NAME}" ] || [ -n "${CYB3RHQ_AGENT_GROUP}" ] || [ -n "${ENROLLMENT_DELAY}" ] || [ -n "${CYB3RHQ_REGISTRATION_PASSWORD}" ]; then
        add_auto_enrollment
        set_auto_enrollment_tag_value "manager_address" "${CYB3RHQ_REGISTRATION_SERVER}"
        set_auto_enrollment_tag_value "port" "${CYB3RHQ_REGISTRATION_PORT}"
        set_auto_enrollment_tag_value "server_ca_path" "${CYB3RHQ_REGISTRATION_CA}"
        set_auto_enrollment_tag_value "agent_certificate_path" "${CYB3RHQ_REGISTRATION_CERTIFICATE}"
        set_auto_enrollment_tag_value "agent_key_path" "${CYB3RHQ_REGISTRATION_KEY}"
        set_auto_enrollment_tag_value "authorization_pass_path" "${CYB3RHQ_REGISTRATION_PASSWORD_PATH}"
        set_auto_enrollment_tag_value "agent_name" "${CYB3RHQ_AGENT_NAME}"
        set_auto_enrollment_tag_value "groups" "${CYB3RHQ_AGENT_GROUP}"
        set_auto_enrollment_tag_value "delay_after_enrollment" "${ENROLLMENT_DELAY}"
        delete_blank_lines "${TMP_ENROLLMENT}"
        concat_conf
    fi

            
    if [ -n "${CYB3RHQ_REGISTRATION_PASSWORD}" ]; then
        echo "${CYB3RHQ_REGISTRATION_PASSWORD}" > "${INSTALLDIR}/${CYB3RHQ_REGISTRATION_PASSWORD_PATH}"
        chmod 640 "${INSTALLDIR}"/"${CYB3RHQ_REGISTRATION_PASSWORD_PATH}"
        chown root:cyb3rhq "${INSTALLDIR}"/"${CYB3RHQ_REGISTRATION_PASSWORD_PATH}"
    fi

    # Options to be modified in ossec.conf
    edit_value_tag "notify_time" "${CYB3RHQ_KEEP_ALIVE_INTERVAL}"
    edit_value_tag "time-reconnect" "${CYB3RHQ_TIME_RECONNECT}"

    unset_vars

}

# Start script execution
main "$@"
