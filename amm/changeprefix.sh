#!/usr/bin/bash


VNODE_DOMAIN_PREFIX=$1

#if [[ $VNODE_DOMAIN_PREFIX =~ ^(?!(epic))(?![0-9])(?![\-])[-a-z0-9]*[-a-z]$ ]]; then

if [[ $VNODE_DOMAIN_PREFIX =~ ^(epic) ]]; then
        echo "Not Valid Prefix - epic."
	exit 1
fi

if [[ $VNODE_DOMAIN_PREFIX =~ ^([0-9]) ]]; then
        echo "Not Valid Prefix - starts with number."
	exit 1
fi

if [[ $VNODE_DOMAIN_PREFIX =~ ^([\-]) ]]; then
        echo "Not Valid Prefix - starts with dash."
	exit 1
fi

len=${#VNODE_DOMAIN_PREFIX}
if [ "$len" -gt "32" ]; then
        echo "Not Valid Prefix. Invalid length"
        exit 1
fi

if [[ $VNODE_DOMAIN_PREFIX =~ [-a-z0-9]*[-a-z]$ ]]; then
	echo "Valid prefix."
else
	echo "Not Valid Prefix."
	exit 1
fi


#bdconfig --set bdshared_global_bdprefix="$VNODE_DOMAIN_PREFIX"

#ERTS_PATH=/opt/bluedata/common-install/bd_mgmt/erts-*/bin
#NAME_ARG=`egrep '^-s?name' $ERTS_PATH/../../releases/1/vm.args`
#RPCCMD="$ERTS_PATH/escript $ERTS_PATH/nodetool $NAME_ARG -setcookie cookie rpcterms"
#$RPCCMD bd_mgmt_config update "bdshared_global_bdprefix. \"$VNODE_DOMAIN_PREFIX\"."


