package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"syscall"
)

const version = "0.3.2"
const allowedEmail = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.@"

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

func printBuildInfo() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatal("Can't read BuildInfo")
	}

	fmt.Println("pwch version:")
	fmt.Printf("  %s\n", version)

	fmt.Println("Built with:")
	fmt.Printf("  %s\n", buildInfo.GoVersion)

	fmt.Println("Dependencies:")
	if len(buildInfo.Deps) > 0 {
		for _, dep := range buildInfo.Deps {
			fmt.Printf("  %s \t %s\n", dep.Path, dep.Version)
		}
	} else {
		fmt.Println("  no external dependencies")
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] != "" {
		behavior := os.Args[1]

		// print pwch version and build info
		if behavior == "--version" {
			printBuildInfo()
			os.Exit(0)
		}

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
		if behavior == "swap" {
			var email string
			var oldHashString string
			var newHashString string

			fmt.Scanf("%s", &email)
			fmt.Scanf("%s", &oldHashString)
			fmt.Scanf("%s", &newHashString)

			// prevent command injection
			if !isAllowed(email, allowedEmail) {
				os.Exit(1)
			}

			cmd := exec.Command("/bin/doveadm", "mailbox", "cryptokey", "password", "-u", email, "-O", "-U")

			var input bytes.Buffer
			input.Write([]byte(oldHashString + "\n" + newHashString + "\n"))

			cmd.Stdin = &input

			err := cmd.Run()
			if err != nil {
				errorHandler(err)
			}
			os.Exit(0)
		}
	}
}
