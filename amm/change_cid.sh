
VNODE_CID="Cat Tower"
bdconfig --set bdshared_global_cin="$VNODE_CID"


ERTS_PATH=/opt/bluedata/common-install/bd_mgmt/erts-*/bin
NAME_ARG=`egrep '^-s?name' $ERTS_PATH/../../releases/1/vm.args`
RPCCMD="$ERTS_PATH/escript $ERTS_PATH/nodetool $NAME_ARG -setcookie cookie rpcterms"
$RPCCMD bd_mgmt_config update "bdshared_global_cin. \"$VNODE_CID\"."

