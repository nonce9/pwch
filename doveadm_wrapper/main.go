package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const allowedEmail = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.@"
const allowedPassword = "0123456789abcdef"

func isAllowed(input string, allowed string) bool {
	for i := 0; i < len(input); i++ {
		if !strings.ContainsAny(input, allowed) {
			return false
		}
	}
	return true
}

func errorHandler(err error) {
	if exitErr, ok := err.(*exec.ExitError); ok {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			os.Exit(status.ExitStatus())
		}
	}
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(-1)
}

func main() {
	if os.Args[1] != "" {
		behavior := os.Args[1]

		// terminate imap sessions
		if behavior == "kick" && os.Args[2] != "" && isAllowed(os.Args[2], allowedEmail) {
			cmd := exec.Command("/bin/doveadm", "kick", os.Args[2])
			err := cmd.Run()
			if err != nil {
				errorHandler(err)
			}
			os.Exit(0)
		}

		// reencrypt mailbox
		if behavior == "swap" && os.Args[2] != "" && os.Args[3] != "" && os.Args[4] != "" &&
			isAllowed(os.Args[2], allowedEmail) && isAllowed(os.Args[3], allowedPassword) && isAllowed(os.Args[4], allowedPassword) {

			cmd := exec.Command("/bin/doveadm", "mailbox", "cryptokey", "password", "-u", os.Args[2], "-o", os.Args[3], "-n", os.Args[4])
			err := cmd.Run()
			if err != nil {
				errorHandler(err)
			}
			os.Exit(0)
		}
	}
}
