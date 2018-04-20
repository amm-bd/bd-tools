#!/bin/env bash
################################################################################
# Copyright (c) 2015, BlueData Software, Inc.                                  #
#                                                                              #
# This file contains various Operating system specific validation checks.      #
################################################################################

source ${VBASE_DIR}/tests-common.sh

MIN_KERNEL_VERSION='2.6.32-573'
MIN_KERNEL_VERS=($(echo ${MIN_KERNEL_VERSION} | tr '.' ' ' | tr '-' ' '))

CENTOS_REL_FILE="/etc/centos-release"
REDHAT_REL_FILE='/etc/redhat-release'

# Check for centos first because on CentOS both the files exist.
if [[ -e $CENTOS_REL_FILE ]];
then
    OS_TYPE=$OS_CENTOS
    OS_REL_FILE=$CENTOS_REL_FILE
elif [[ -e $REDHAT_REL_FILE ]];
then
    OS_TYPE=$OS_RHEL
    OS_REL_FILE=$REDHAT_REL_FILE
else
    OS_TYPE='unknown-os-type'
    OS_REL_FILE='unknown-file'
fi

OS_MAJOR=$(util_get_os_major)

## Checks for a supported OS(CentOS or RHEL only)
validate_os_type() {
    test_name "OS type"

    if [ "${OS_TYPE}" == "${OS_CENTOS}" ] || [ "${OS_TYPE}" == "${OS_RHEL}" ]; then
        test_status ${TEST_STATUS_SUCCESS}
    else
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "Unknown OS Type. Exiting validation."

        # This is a fatal error, no point continuing
        exit ${TESTGROUP_FATAL}
    fi
}

# Check if CONFIG_SECCOMP is built into this kernel, and warn if not. HAATHI-12734
check_seccomp_kernel_feature() {
    test_name "CONFIG_SECCOMP enabled in kernel"
    filename=/boot/config-$(uname -r)
    is_supported=$( cat $filename | grep "CONFIG_SECCOMP=y" )
    if [ "$is_supported" != "CONFIG_SECCOMP=y" ]; then
        test_status ${TEST_STATUS_WARNING}
        test_additional_desc "CONFIG_SECCOMP must be enabled for security."
    else
        test_status ${TEST_STATUS_SUCCESS}
    fi
}

# Check if docker is installed, and if so, if it's compatible with EPIC. HAATHI-13456
validate_docker_version() {
    test_name "Docker version"
    if [[ "$OS_MAJOR" == "7" ]];
    then
        # Check to see if docker is even installed.

        if [ -z "$( rpm -qa --queryformat '%{NAME}\n' | grep ^docker$ )" ]; then
            # No installed docker version to compare against.
            test_status ${TEST_STATUS_SUCCESS}
        else
            # Docker is installed. Check to see if its version is compatible.
            
            prefix="docker-"
            DOCKER_VERSION=${DOCKER#$prefix}
	    
            INSTALLED_DOCKER_VERSION=$(rpm -q --queryformat '%{VERSION}' docker)
            test_additional_desc "test version: $DOCKER_VERSION. Installed Version: $INSTALLED_DOCKER_VERSION."
            if [[ $INSTALLED_DOCKER_VERSION == $DOCKER_VERSION ]]; then
                test_status ${TEST_STATUS_SUCCESS}
                test_additional_desc "Installed Docker version: $INSTALLED_DOCKER_VERSION"
            else
                test_status ${TEST_STATUS_FAILURE}
                test_additional_desc "Incompatible installed Docker version $INSTALLED_DOCKER_VERSION. Exiting Validation"
                exit ${TESTGROUP_FATAL}
            fi    
        fi
    else
        # OS version isn't 7, so we don't need to deal with this.
        test_status ${TEST_STATUS_SUCCESS}
    fi
}

validate_kernel_version() {
    test_name "running kernel version"

    VERS=($(uname -r | tr '.' ' ' | tr '-' ' ')) # 2 6 32 573 (rest we don't care)

    COUNT=0
    PASSED='true'
    LENGTH=${#MIN_KERNEL_VERS[@]}
    while [[ ${COUNT} -lt ${LENGTH} ]];
    do
        if [[ ${VERS[${COUNT}]} -gt ${MIN_KERNEL_VERS[${COUNT}]} ]];
        then
            # Values at the lower indexes have higher preference.
            #
            # For example, if VERS[1] = 36 and MIN_KERNEL_VERS[1] = 32. There is
            # no need to check the next element in the array. Infact, checking
            # that would be wrong as it is most likely to be a smaller number.
            PASSED='true'
            break
        elif [[ ${VERS[${COUNT}]} -lt ${MIN_KERNEL_VERS[${COUNT}]} ]];
        then
            PASSED='false'
            break
        fi
        COUNT=$((${COUNT} + 1))
    done

    if [[ "${PASSED}" == 'false' ]];
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "Kernel version must atleast be ${MIN_KERNEL_VERSION}"
    else
        test_status ${TEST_STATUS_SUCCESS}
    fi
}

## Checks for an RHEL subscription
validate_rhel_subscription(){
    if [ $OS_TYPE == $OS_RHEL ]; then
        HAS_SERVER=false
        HAS_SERVER_HA=false
        HAS_EXTRA_SERVER=false
        HAS_SERVER_OPTIONAL=false

        ADDITONAL_DESC=''

        test_name "RHEL Subscription"
        SUBSCRIPTION_TYPE=$(log_sudo_exec subscription-manager version | grep "server type:" | sed -e 's/server type://g')
        if [[ "${SUBSCRIPTION_TYPE}" == *"Classic"* ]];
        then
            SERVER="rhel-x86_64-server-${OS_MAJOR}.z"
            SERVER_HA="rhel-x86_64-server-ha-${OS_MAJOR}.z"
            SERVER_OPTIONAL="rhel-x86_64-server-optional-${OS_MAJOR}.z"
            SERVER_LB="rhel-x86_64-server-lb-${OS_MAJOR}.z"

            # Classic subscription
            # Just make sure options and ha channels are enabled.
            CHANNELS=$(log_sudo_exec rhn-channel --list | xargs)
            for CHAN in ${CHANNELS};
            do
                [[ "$CHAN" == *"server-${OS_MAJOR}"* ]] && HAS_SERVER=true
                [[ "$CHAN" == *"server-ha-${OS_MAJOR}"* ]] && HAS_SERVER_HA=true
                [[ "$CHAN" == *"server-optional-${OS_MAJOR}"* ]] && HAS_SERVER_OPTIONAL=true
                [[ "$CHAN" == *"server-lb-${OS_MAJOR}"* ]] && HAS_LB_SERVER=true
            done
        elif [[ "${SUBSCRIPTION_TYPE}" == *"Subscription Management"* ]];
        then
            SERVER="rhel-${OS_MAJOR}-server-rpms"
            SERVER_HA="rhel-${OS_MAJOR}-server-optional-rpms"
            SERVER_OPTIONAL="rhel-ha-for-rhel-${OS_MAJOR}-server-rpms"
            SERVER_LB="rhel-lb-for-rhel-6-server-rpms"
            SERVER_EXTRA="rhel-7-server-extras-rpms"

            # Newer subscription
            ENABLED_REPOS=$(log_sudo_exec subscription-manager repos --list-enabled | grep  "Repo ID:" | awk '{print $3}' | xargs)
            for REPO in ${ENABLED_REPOS};
            do
                [[ "$REPO" == "${SERVER}" ]] && HAS_SERVER=true
                [[ "$REPO" == "${SERVER_HA}" ]] && HAS_SERVER_HA=true
                [[ "$REPO" == "${SERVER_OPTIONAL}" ]] && HAS_SERVER_OPTIONAL=true
                [[ "${OS_MAJOR}" == '6' && "$REPO" == "${SERVER_LB}" ]] && HAS_LB_SERVER=true
                [[ "${OS_MAJOR}" == '7' && "$REPO" == "${SERVER_EXTRA}" ]] && HAS_EXTRA_SERVER=true
            done
        else
            test_status ${TEST_STATUS_FORCE_SUCCESS}
            test_additional_desc "Unknown subscription type: ${SUBSCRIPTION_TYPE}"
            return
        fi

        if [ ${HAS_SERVER} != 'true' ] || [ ${HAS_SERVER_HA} != 'true' ] ||    \
                [ ${HAS_SERVER_OPTIONAL} != 'true' ] ||                        \
                [[ "${OS_MAJOR}" == '6' && "${HAS_LB_SERVER}" != 'true' ]] ||  \
                [[ "${OS_MAJOR}" == '7' && "${HAS_EXTRA_SERVER}" != 'true' ]];
        then
            # Almost every enterprise customer so far had to override this as they
            # have a RHEL subscription that doesn't conform to the names we check.
            # So, a warning seems more appropriate. If nothing else, this will
            # list the repos we need.
            test_status ${TEST_STATUS_WARNING}

            if [[ "${HAS_SERVER}" != true ]];
            then
                test_additional_desc "Missing channel/repo: ${SERVER}"
            fi

            if [[ "${HAS_SERVER_HA}" != true ]];
            then
                test_additional_desc "Missing channel/repo: ${SERVER_HA}"
            fi

            if [[ "${HAS_SERVER_OPTIONAL}" != true ]];
            then
                test_additional_desc "Missing channel/repo: ${SERVER_OPTIONAL}"
            fi

            if [[ "${OS_MAJOR}" == '6' ]] && [[ "${HAS_LB_SERVER}" != true ]];
            then
                test_additional_desc "Missing channel/repo: ${SERVER_LB}"
            fi

            if [[ "${OS_MAJOR}" == '7' ]] && [[ "${HAS_EXTRA_SERVER}" != true ]];
            then
                test_additional_desc "Missing channel/repo: ${SERVER_EXTRA}"
            fi
        else
            test_status ${TEST_STATUS_SUCCESS}
        fi
    fi
}

# SELinux must not be 'disabled'. Both 'permissive' and 'enforcing' are okay.
validate_selinux() {
    test_name "SELinux setting"

    ENFORCEMENT=$(getenforce | tr [:upper:] [:lower:])
    if [[ "$ENFORCEMENT" == 'disabled' ]];
    then
        test_status ${TEST_STATUS_WARNING}
        test_additional_desc "SElinux is disabled."
        util_add_config_param "bds_prechecks_selinux=false"
    else
        test_status ${TEST_STATUS_SUCCESS}
        util_add_config_param "bds_prechecks_selinux=true"
    fi
}

# SELinux must not be 'disabled'. Both 'permissive' and 'enforcing' are okay.
validate_selinux_for_upgrade() {
    test_name "SELinux setting"
    eval "$(bdconfig --getfewenv bds_prechecks_selinux)"
    ENFORCEMENT=$(getenforce | tr [:upper:] [:lower:])
    if [[ "$ENFORCEMENT" == 'disabled' ]];
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "SElinux is disabled."
        return
    fi
    test_status ${TEST_STATUS_SUCCESS}
}

## Validate IP Tables are running
validate_ip_tables() {
    test_name "IPtables/Firewalld configuration"

    local CONFIGURE_IPTABLES="true"

    if [ "$NODE" == "$NODE_PROXY" ]
    then
        test_status ${TEST_STATUS_SUCCESS}
        test_additional_desc "IPtables/Firewalld will be disabled on proxy node."
        util_add_config_param "bds_prechecks_iptables=false"
        return
    fi

    if [ "$OS_MAJOR" == "7" ]
    then
        # We have to check either firewalld is enabled or iptables is enabled
        FIREWALLD_CONFIG=$(systemctl is-enabled firewalld 2>/dev/null)
        if [[ "${FIREWALLD_CONFIG}" != "enabled" ]];
        then
            CONFIGURE_IPTABLES='false'
        elif [[ -z "${FIREWALLD_CONFIG}" ]];
        then
            # Only check IPTables if Firewalld is not installed. An empty response
            # for the is-enabled call means the unit is not installed.
            IP_TABLES_CONFIG=$(systemctl is-enabled iptables 2>/dev/null)
            if [[ "${IP_TABLES_CONFIG}" != "enabled" ]];
            then
                CONFIGURE_IPTABLES='false'
            elif [[ -z "${IP_TABLES_CONFIG}" ]];
            then
                CONFIGURE_IPTABLES='false'
            fi
        fi
    else
        # iptables should be ON for level 3
        IP_TABLES_CONFIG=$(chkconfig --list iptables 2>/dev/null | awk '{print $5}')
        STATUS=(${IP_TABLES_CONFIG/:/ })
        if [[ "${STATUS[1]}" != "on" ]];
        then
            CONFIGURE_IPTABLES='false'
        fi
    fi

    if [ "$OS_MAJOR" == "7" ]
    then
        # Check IPtables/Firewalld's current running status irresprective of
        # it's configured status.
        log_sudo_file_exec_no_error systemctl is-active firewalld
        IPTABLES_RUNNING_STATUS="$?"

        if [[ ${IPTABLES_RUNNING_STATUS} -ne 0 ]];
        then
            # Check if IPTables is running just in case.
            log_sudo_file_exec_no_error systemctl is-active iptables
            IPTABLES_RUNNING_STATUS="$?"
        fi
    else
        # check if the service iptables is running
        log_sudo_file_exec_no_error service iptables status
        IPTABLES_RUNNING_STATUS="$?"
    fi

    if [[ "${CONFIGURE_IPTABLES}" == 'false' && "${IPTABLES_RUNNING_STATUS}" == '0' ]];
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "IPtables/Firewalld is running now but not configured to start at system bootup."
        return
    elif [[ "${CONFIGURE_IPTABLES}" == 'true' && "${IPTABLES_RUNNING_STATUS}" != '0' ]];
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "IPtables/Firewalld is configured to start at bootup but not running now."
        return
    fi

    # Just show a general warning if IPTables/Firewalld is not running.
    if [ ${IPTABLES_RUNNING_STATUS} -ne 0 ];
    then
        test_status ${TEST_STATUS_WARNING}
        test_additional_desc "IPtables/Firewalld is not running."
        util_add_config_param "bds_prechecks_iptables=false"
    else
        test_status ${TEST_STATUS_SUCCESS}
        util_add_config_param "bds_prechecks_iptables=true"
    fi
}

validate_ip_tables_for_upgrade() {
    test_name "IPtables/Firewalld configuration"

    eval "$(bdconfig --getfewenv bds_prechecks_iptables)"

    if [ "$bds_global_purpose" == "$NODE_PROXY" ]
    then
        if [ "$bds_prechecks_iptables" != "false" ]
        then
            test_status ${TEST_STATUS_FAILURE}
        else
            test_status ${TEST_STATUS_SUCCESS}
        fi
        test_additional_desc "IPtables/Firewalld should be disabled on proxy node."
        return
    fi

    if [ "$OS_MAJOR" == "7" ]
    then
        # Check IPtables/Firewalld's current running status irresprective of
        # it's configured status.
        log_sudo_file_exec_no_error systemctl is-active firewalld
        IPTABLES_RUNNING_STATUS="$?"

        if [[ ${IPTABLES_RUNNING_STATUS} -ne 0 ]];
        then
            # Check if IPTables is running just in case.
            log_sudo_file_exec_no_error systemctl is-active iptables
            IPTABLES_RUNNING_STATUS="$?"
        fi
    else
        # check if the service iptables is running
        log_sudo_file_exec_no_error service iptables status
        IPTABLES_RUNNING_STATUS="$?"
    fi

    if [ ${IPTABLES_RUNNING_STATUS} -ne 0 ]
    then
        if [ "$bds_prechecks_iptables" == "true" ]
        then
            # case when iptables was running during install
            # and not running before upgrade - FAIL
            test_status ${TEST_STATUS_FAILURE}
        else
            # case when iptables was running during install
            # and is still running - PASS
            test_status ${TEST_STATUS_SUCCESS}
        fi
    else
        if [ "$bds_prechecks_iptables" == "false" ]
        then
            # case when iptables was disabled during install
            # and is running before upgrade - FAIL
            test_status ${TEST_STATUS_FAILURE}
        else
            # case when iptables was disabled during install
            # and is still not - PASS
            test_status ${TEST_STATUS_SUCCESS}
        fi
    fi
}

## Checks for the properly configured Automount
## Returns success if no autofs is installed (Installation takes care of that)
## writes to the config file for a properly configured Automount
## returns boolean
verify_automount() {
    test_name "automount configuration"
    local AUTOMOUNT=/etc/auto.master
    local AUTOMOUNT_ROOT="/net/"

    if ! rpm -q --quiet --whatprovides autofs;
    then
        # Autofs is not installed. Installation will take care of installing and
        # configuring it.
        test_status ${TEST_STATUS_SUCCESS}

        # Add the default root to the config file so, we have it available when
        # the installer installs the autofs rpm.
        util_add_config_param "bds_global_automountroot=\"${AUTOMOUNT_ROOT}\""
        return
    else
        AUTOMOUNT_ROOT=( $(grep -- [[:space:]]-hosts $AUTOMOUNT | grep "^[^#]" | sed 's/^\(^\S\S*\)\s.*/\1/' | xargs) )
        local COUNT=${#AUTOMOUNT_ROOT[@]}

        if [ $COUNT -ne 1 ]
        then
            test_status ${TEST_STATUS_FAILURE}
            test_additional_desc "Only one '-hosts' entry expected in auto.master file."
            return
        fi
    fi

    [ "${AUTOMOUNT_ROOT: -1}" != "/" ] && AUTOMOUNT_ROOT=$AUTOMOUNT_ROOT"/"

    if [ "$NODE" == "$NODE_WORKER" ] && [ "$AUTOMOUNT_ROOT" != "$CONTROLLER_AUTOMOUNT_ROOT" ];
    then
        log_file "Worker automount dir: ${AUTOMOUNT_ROOT}"
        log_file "Controller automount dir: ${CONTROLLER_AUTOMOUNT_ROOT}"

        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "Automount dir (on worker) doesn't match that of controller's."
        return
    fi

    util_add_config_param "bds_global_automountroot=\"${AUTOMOUNT_ROOT}\""
    test_status ${TEST_STATUS_SUCCESS}
}

## Validate SSH Config file for root login permission to be true
## Validate for SSH Deamon installed and enabled
validate_ssh_config() {
    test_name "SSHD configuration"

    local FAILED='false'

    which sshd > /dev/null
    if [[ $? -ne 0 ]];
    then
        test_status ${TEST_STATUS_FORCE_SUCCESS}
        test_additional_desc "SSHD not found. Install 'openssh-server' package."

        # No point in continuing sshd checks.
        return
    fi

    if [ "$OS_MAJOR" == "7" ]
    then
        systemctl is-enabled sshd | grep -w enabled > /dev/null
    else
        chkconfig --list sshd | awk '{print $5}' | grep -w on > /dev/null
    fi
    if [[ $? -ne 0 ]];
    then
        test_status ${TEST_STATUS_FORCE_SUCCESS}
        test_additional_desc "SSHD must be configured to start at bootup."
        FAILED='true'
    fi

    if $(util_is_docker);
    then
        log_sudo_exec_no_exit "grep -qE '^Port\s22$|^#Port\s22$' /etc/ssh/sshd_config"
        if [[ $? -ne 0 ]];
        then
            [[ "${FAILED}" != 'true' ]] && test_status ${TEST_STATUS_FAILURE}
            test_additional_desc "SSHD must be running on port 22."
            FAILED='true'
        fi
    fi

    # If our services will be running as "root", then permitrootlogin must be allowed
    if [[ "$BLUEDATA_USER" == "root" ]];
    then
        # Make sure PermitRootLogin is not set to no
        log_sudo_file_exec grep -e "^PermitRootLogin.*no" "/etc/ssh/sshd_config"
        if [[ $? -eq 0 ]];
        then
            [[ "${FAILED}" != 'true' ]] && test_status ${TEST_STATUS_FAILURE}
            test_additional_desc "SSHD must allow root user to login"
            FAILED='true'
        fi
    fi

    # Check to see id_rsa key is already present, in which case we want to make
    # the key is in the authorized_keys as well. fail otherwise
    if [ "$NODE" == "$NODE_CONTROLLER" ];
    then
        SSH_FOLDER="$(eval echo "~$BLUEDATA_USER")/.ssh"
        SSHKEY="$SSH_FOLDER/id_rsa"
        if [ -f "$SSHKEY" ]
        then
            Status=$(log_su_exec_no_exit $BLUEDATA_USER "ssh -q -o BatchMode=yes -o StrictHostKeyChecking=no -i $SSHKEY localhost echo ok")
            if [ "$Status" != "ok" ]; then
                test_status ${TEST_STATUS_FAILURE}
                test_additional_desc "A valid keypair is present under $SSH_FOLDER. Either remove them or add $SSH_FOLDER/id_rsa.pub to $SSH_FOLDER/authorized_keys."
                FAILED='true'
            fi
        fi
    fi

    if [ "${FAILED}" == 'false' ]; then
        test_status ${TEST_STATUS_SUCCESS}
    fi
}

## Validate rsyslog.conf file.
validate_rsyslog_conf() {
    test_name "rsyslog setting"

    local FAILED='false'
    log_sudo_exec_no_exit grep -q \'^\$IncludeConfig.*conf$\' '/etc/rsyslog.conf'
    if [[ $? -ne 0 ]];
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "/etc/rsyslog.conf file must include '/etc/rsyslog.d/*.conf' directory."
        FAILED='true'
    fi

    log_sudo_exec_no_exit grep -q \'^\$ModLoad.*imuxsock\' '/etc/rsyslog.conf'
    if [[ $? -ne 0 ]];
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "imuxsock is not loaded in /etc/rsyslog.conf."
        FAILED='true'
    fi

    if [ "${FAILED}" == 'false' ]; then
        test_status ${TEST_STATUS_SUCCESS}
    fi
}

validate_rsyslog_conf_for_upgrade() {
    test_name "rsyslog setting"

    if [ -s "/etc/rsyslog.conf" ] && [ -s "/etc/rsyslog.d/bds.conf" ]
    then
        test_status ${TEST_STATUS_SUCCESS}
    else
        test_status ${TEST_STATUS_FAILURE}
    fi
}

validate_software_raid() {
    test_name "for software RAID"

    log_exec_no_exit "lsblk | egrep -i 'linear|RAID0|RAID1|RAID4|RAID5|RAID6|RAID10|MULTIPATH|FAULTY|CONTAINER'"
    if [[ $? -eq 0 ]];
    then
        test_status ${TEST_STATUS_FORCE_SUCCESS}
        return
    fi

    test_status ${TEST_STATUS_SUCCESS}
}

validate_keytab_file() {
    test_name "for krb5.keytab"

    # Check to make sure /etc/krb5.keytab doesn't exist, show a warning if it does
    if [ -f /etc/krb5.keytab ]
    then
        test_status ${TEST_STATUS_WARNING}
        test_additional_desc "/etc/krb5.keytab already exists."
        return
    fi

    test_status ${TEST_STATUS_SUCCESS}
}

validate_user_privileges() {
    local FAILED='false'
    test_name "user and group specified"

    if [ -z "$BLUEDATA_USER" ] || [ -z "$BLUEDATA_GROUP" ]
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "Valid user and group must be specified using --user and --group options."
        return
    fi

    log_file_exec "id -u $BLUEDATA_USER 2>/dev/null"
    if [[ $? -ne 0 ]];
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "user:$BLUEDATA_USER is not present."
        FAILED='true'
    fi

    log_file_exec "id -Gn $BLUEDATA_USER 2>/dev/null | grep -qw $BLUEDATA_GROUP";
    if [[ $? -ne 0 ]];
    then
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "user:$BLUEDATA_USER doesn't belong to group:$BLUEDATA_GROUP."
        FAILED='true'
    fi

    # XXX FIXME. Will only work if sudo is the actual command. Basically we need
    # a better way of validating (dryrun for our commands)
    # For non-root user, check to make sure we are allowed to run all commands
    # without passwd
#    if [ "$BLUEDATA_USER" != "root" ]; then
#        allowedSudoCmds=$(log_su_exec $BLUEDATA_USER "sudo -nl")
        # We have to run through all the sudo commands to
        # make sure we can run those commands
        # But if sudoers has ALL, then we can skip the check
#        echo $allowedSudoCmds | grep -q "NOPASSWD.*ALL"
#        if [[  $? -ne 0 ]]
#        then
#            while read cmd || [[ -n "$cmd" ]]; do
                # Check to see if this command can be run as sudo for $BLUEDATA_USER
                # Skip comments and Defaults command
#                [[ "$cmd" =~ ^#.*$ ]] && continue
#                [[ "$cmd" == Defaults* ]] && continue
#                actualCmd=$(echo $cmd | sed 's/^.*NOPASSWD/NOPASSWD/')
#                echo $allowedSudoCmds | grep -qw "$actualCmd"
#                if [[  $? -ne 0 ]]
#                then
#                    test_status ${TEST_STATUS_FAILURE}
#                    test_additional_desc "$cmd must be allowed for sudo access for $BLUEDATA_USER user"
#                    FAILED='true'
#                fi
#            done < "${VBASE_DIR}/sudoers.conf"
#        fi
#    fi

    if [ "${FAILED}" == 'false' ]; then
        test_status ${TEST_STATUS_SUCCESS}
        util_add_config_param "bds_global_user=\"${BLUEDATA_USER}\""
        util_add_config_param "bds_global_group=\"${BLUEDATA_GROUP}\""
    fi
}

validate_ssl_creds() {
    if [ -n "${SSL_CERT}" ] && [ -n "${SSL_PRIV_KEY}" ];
    then
        test_name "SSL server certificate and private key"
        # Check to make sure SSL related file paths are absolute paths
        if [[ "${SSL_CERT}" != /* ]] || [[ "${SSL_PRIV_KEY}" != /* ]];
        then
            test_status ${TEST_STATUS_FAILURE}
            test_additional_desc "Provide an absolute path for SSL certificate and private key."
            return
        fi
        # Check to make sure SSL related files exist
        if [[ -f "${SSL_CERT}" && -f "${SSL_PRIV_KEY}" ]];
        then
            test_status ${TEST_STATUS_SUCCESS}
            util_add_config_param "bds_prechecks_sslcert=\"${SSL_CERT}\""
            util_add_config_param "bds_prechecks_sslkey=\"${SSL_PRIV_KEY}\""
            return
        fi
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "Provide a valid SSL certificate and private key."
    fi
}

validate_cgconfig() {
    test_name "cgconfig kernel params"
    OUT=$(log_sudo_exec "cat /proc/cmdline" | tr ' ' '\n' | grep 'cgconfig_disable' | cut -d'=' -f 2)
    if [[ $? -eq 0 ]];
    then
        # Found a kernel boot param that disables some cgconfigs.
        test_status ${TEST_STATUS_FAILURE}
        test_additional_desc "$OUT were disabled in cgconfig"
    else
        test_status ${TEST_STATUS_SUCCESS}
    fi
}

# Start Operating system configuration tests
test_group "Operating system configuration"

if [[ "$UPGRADE" == "false" ]];
then
    validate_os_type
    validate_rhel_subscription

    validate_kernel_version
    check_seccomp_kernel_feature

    validate_docker_version

    validate_selinux
    validate_ip_tables

    if [ "$NODE" != "$NODE_PROXY" ];
    then
        verify_automount
    fi

    if [ "$AGENT_INSTALL" != "true" ]
    then
        validate_ssh_config
    fi

    validate_rsyslog_conf

    validate_user_privileges

    if [ "$NODE" != "$NODE_PROXY" ];
    then
        validate_software_raid

        validate_keytab_file
        validate_ssl_creds
    fi

    validate_cgconfig
else
    validate_rhel_subscription
    validate_selinux_for_upgrade
    validate_ip_tables_for_upgrade
    validate_rsyslog_conf_for_upgrade
    validate_user_privileges
    if [ "$NODE" != "$NODE_PROXY" ];
    then
        validate_ssl_creds
    fi

    validate_cgconfig
fi

# End of all tests for this group.
test_group_complete
