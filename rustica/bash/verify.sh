#!/bin/bash
rm $LOGIN_SCRIPT

function start_user_shell() {
	if [ "$FORCE_COMMAND" != "" ]; then
		eval $FORCE_COMMAND
		exit 0;
	fi

	USER_INFO=$(cat /etc/passwd | grep \^`whoami`\:)
	SHELL=$(echo $USER_INFO | awk '{split($0,p,":"); print p[7]}')
    if [ "$SHELL" = "" ]; then
        echo "Could not locate appropriate shell" 
        SHELL="/bin/bash"
    fi
	eval $SHELL
}

IFS=',' read -ra HOSTNAME <<< "$RUSTICA_AUTHORIZED_HOSTS"
HOSTKEY=$(ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub | cut -d ' ' -f 2 | cut -c 8-)
for i in "${HOSTNAME[@]}"; do
	if [ "$i" = "$HOSTKEY" ]; then
        echo "Authentication Successful."
		start_user_shell
		exit 0;
	fi
done

echo "Not authorized for this server."
exit 1;