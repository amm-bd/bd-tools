

OS_MAJOR="7"
DOCKER="1.14.*"
TEST_STATUS_SUCCESS="success"
TEST_STATUS_FAILURE="failure"

validate_docker_version() {
    
    if [[ "$OS_MAJOR" == "7" ]];
    then
        # Check to see if docker is even installed.

        prefix="docker-"
        DOCKER_VERSION=${DOCKER#$prefix}
        INSTALLED_DOCKER_VERSION=$(rpm -q --queryformat '%{VERSION}' --whatprovides docker)
        
        if [[ $INSTALLED_DOCKER_VERSION == $DOCKER_VERSION ]]; then
            # Docker version is compatible.
            test_status ${TEST_STATUS_SUCCESS}
            
        else
            if [[ $INSTALLED_DOCKER_VERSION = *"no package provides"* ]]; then
                # It's OK if docker is not installed.
                test_status ${TEST_STATUS_SUCCESS}
            else
                # Docker is installed, but it's not our supported version, so fail the test.
                test_status ${TEST_STATUS_FAILURE}
                test_additional_desc "Only docker $DOCKER_VERSION supported. Found docker $INSTALLED_DOCKER_VERSION."
            fi
        fi
    fi
}


validate_docker_version
