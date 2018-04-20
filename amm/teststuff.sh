
RAW_DOCKER="docker-1.13.*"
prefix="docker-"
DOCKER_VERSION=${RAW_DOCKER#$prefix}

echo Docker: $DOCKER_VERSION

if [ -z "$(rpm -qa|grep docker)" ]; then
    echo No docker installed.
    exit 0
fi

        # Check to see if docker version works for us.
        INSTALLED_DOCKER_VERSION=$(rpm -q --queryformat '%{VERSION}' docker)
        if [[ $INSTALLED_DOCKER_VERSION  == $DOCKER_VERSION ]]; then
            echo Compatible Docker!
        else
            echo Incompatible docker! DOCKER: $DOCKER INSTALLED: $INSTALLED_DOCKER_VERSION
        fi

