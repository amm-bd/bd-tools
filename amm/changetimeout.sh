#!/usr/bin/bash

VNODE_TIMEOUT=`expr $1`

ERTS_PATH=/opt/bluedata/common-install/bd_mgmt/erts-*/bin
NAME_ARG=`egrep '^-s?name' $ERTS_PATH/../../releases/1/vm.args`
RPCCMD="$ERTS_PATH/escript $ERTS_PATH/nodetool $NAME_ARG -setcookie cookie rpcterms"
$RPCCMD bd_mgmt_config update "session_expiry_hours. $VNODE_TIMEOUT."
