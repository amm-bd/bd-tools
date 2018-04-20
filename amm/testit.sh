if [ -z "$( rpm -qa --queryformat '%{NAME}\n' | grep ^docker$)" ]; then
    echo "Docker is not installed." 
else
    echo "Docker is installed."

fi
