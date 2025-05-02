package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const directoryToRemove = "/home/user/Desktop/dummy"                                        // the directory to remove
const bcryptHashedPassword = "$2a$10$9Rl6cMDKwqqQXJ2uqSaVGe3tb0734J/Rh.qx3sFvNGEe8DHCBdyzq" // the password brypt hashed. "password"
const message = "Test Message"                                                              // message to display when user fails the password the "limit" times
const hideSecurityPassword = true                                                           // hide in terminal the charaters written
const limit = 3

var counter = 0 // number to count the number of tries

func main() {
	initGuardian()
}

// checks if the password is correct, the user has the "limit" tries
func checkPassword(errors int) bool {
	var result = false

	for i := errors; counter < limit; i++ {
		fmt.Println("Security password:")
		var inputText string

		if hideSecurityPassword {
			bytesInput, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return false
			}

			inputText = string(bytesInput)

		} else {
			fmt.Scanln(&inputText)
		}

		inputText = strings.TrimSpace(inputText)
		if checkKey(inputText) {
			result = true
			break
		} else {
			fmt.Println("Wrong key")
		}

		counter++
	}

	return result
}

// decides if deletes the directory or continues the user interaction
func deleteDirectory() {
	os.RemoveAll(directoryToRemove)
}

// search and kills the ssh current sessions in the machine
func killSSHSessions(killAllSshSessions bool) {
	cmd := exec.Command("bash", "-c", "ps aux | grep -i ssh")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	lines := strings.SplitSeq(string(output), "\n")
	for line := range lines {
		if strings.Contains(line, "@pts/") && killAllSshSessions {
			regx := regexp.MustCompile(`\s+`)
			cleanLine := regx.ReplaceAllString(line, " ")

			sliceLine := strings.Split(cleanLine, " ")
			pid := sliceLine[1]

			cmd = exec.Command("bash", "-c", "kill -9 "+pid)
			output, err = cmd.Output()
			if err != nil {
				fmt.Println("Error: ", err)
				return
			}
		} else if strings.Contains(line, "@pts/") && !killAllSshSessions && strings.Contains(line, getCurrentUser()) {
			regx := regexp.MustCompile(`\s+`)
			cleanLine := regx.ReplaceAllString(line, " ")

			sliceLine := strings.Split(cleanLine, " ")
			pid := sliceLine[1]

			cmd = exec.Command("bash", "-c", "kill -9 "+pid)
			output, err = cmd.Output()
			if err != nil {
				fmt.Println("Error: ", err)
				return
			}
		}
	}
}

// gets the current logged user
func getCurrentUser() string {
	cmd := exec.Command("whoami")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error: ", err)
		return ""
	}

	return (strings.TrimSpace(string(output)))
}

// denies the control+c key combination
func initGuardian() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)

	go func() {
		for sig := range sigs {
			if sig == syscall.SIGINT {
				fmt.Println("Input the key")
			}
		}
	}()

	if checkPassword(counter) { // lets continue to the user
		fmt.Println("Correct key")
		return
	} else { // performs the "guardian" action
		fmt.Println("Failed " + strconv.Itoa(limit) + " times.\n" + message)
		deleteDirectory()
		killSSHSessions(true)
		os.Exit(0)
	}

	select {}
}

// checks if the given key is valid
func checkKey(key string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(bcryptHashedPassword), []byte(key))
	return err == nil
}
