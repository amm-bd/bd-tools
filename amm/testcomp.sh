#!/usr/bin/bash



filename=/boot/config-$(uname -r)
is_supported=$( cat $filename | grep "CONFIG_SECCOMP=y" )
    if [ "$is_supported" != "CONFIG_SECCOMP=y" ]; then
        echo "WARNING:  kernel build CONFIG_SECCOMP is NOT enabled."
    else
    echo "kernel build CONFIG_SECCOMP is totally enabled."
    fi
