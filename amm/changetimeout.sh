#!/usr/bin/bash

if [[ $# -ne 1 ]]; then
    echo "Usage:  Enter session expiry hours timeout value as the only argument."
    exit 1
fi

VNODE_TIMEOUT=`expr $1`

ERTS_PATH=/opt/bluedata/common-install/bd_mgmt/erts-*/bin
NAME_ARG=`egrep '^-s?name' $ERTS_PATH/../../releases/1/vm.args`
RPCCMD="$ERTS_PATH/escript $ERTS_PATH/nodetool $NAME_ARG -setcookie cookie rpcterms"
$RPCCMD bd_mgmt_api_identity set_session_expiry_hours $VNODE_TIMEOUT.

