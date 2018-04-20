# .bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
	. ~/.bashrc
fi

# User specific environment and startup programs

PATH=$PATH:$HOME/bin

export PATH

export TEST_SYS=10.32.1.76
export TEST_WORKER_SYS=10.32.1.175
alias gotest='sshpass -padmin123 ssh root@$TEST_SYS'
alias goworker='sshpass -padmin123 ssh root@$TEST_WORKER_SYS'
