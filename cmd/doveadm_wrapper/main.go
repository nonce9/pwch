package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"syscall"
)

const version = "0.3.0"
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
	if len(os.Args) > 1 && os.Args[1] != "" {
		behavior := os.Args[1]

		// print pwch version and build info
		if behavior == "--version" {
			buildInfo, ok := debug.ReadBuildInfo()
			if !ok {
				panic("Can't read BuildInfo")
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
