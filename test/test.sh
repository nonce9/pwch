#!/bin/bash

set -xeu

change_password() 
{
    local MESSAGE_UID="${1}"
    local PASSWORD_OLD="${2}"
    local PASSWORD_NEW="${3}"

    # Request password change link
    curl --silent --output /dev/null \
        -X POST \
        -F 'email=pwch1@localdomain' \
        https://localhost:443/emailSend

    # wait for email being sent
    sleep 1

    # get password change url from mailbox
    CHANGE_PATH=$(curl --silent "imap://localhost/INBOX;UID=${MESSAGE_UID}" \
        -u "pwch1@localdomain:${PASSWORD_OLD}" \
        | grep changePassword \
        | awk -F'?' '{ print $2 }' \
        | tr -d \\r)

    # change password
    curl --silent --output /dev/null \
        -X POST \
        -F "current-password=${PASSWORD_OLD}" \
        -F "new-password=${PASSWORD_NEW}" \
        -F "confirm-password=${PASSWORD_NEW}" \
        "https://localhost:443/submitPassword?${CHANGE_PATH}"
}

change_password "1" "password" "StrongPassword123!"

# cool down rate limiting
sleep 4

change_password "2" "StrongPassword123!" "password"

curl --silent "imap://localhost/INBOX;UID=1" \
    -u "pwch1@localdomain:password" \
    | grep changePassword
