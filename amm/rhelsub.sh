
PASS=$1

yum clean all
subscription-manager register --username=BluedataInc --password=$PASS
subscription-manager attach --auto
subscription-manager repos --disable='*'
subscription-manager repos --enable rhel-7-server-optional-rpms
subscription-manager repos --enable rhel-ha-for-rhel-7-server-rpms
subscription-manager repos --enable rhel-7-server-rpms
subscription-manager repos --enable rhel-7-server-extras-rpms
subscription-manager repos --disable=*-beta-*
