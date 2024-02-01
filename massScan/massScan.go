package massScan

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Alpharivs/massmap/terminator"
)

func Scan(ip, inter, rate string, docker bool) string {
	sudoPath := "/usr/bin/sudo"

	var cmd *exec.Cmd
	if docker {
		cmd = exec.Command(sudoPath, "docker", "run", "-i", "--network", "host", "--rm", "adarnimrod/masscan", "-p1-65535,U:1-65535", ip, "-e", inter, "--rate="+rate, "--wait=5")
	} else {
		cmd = exec.Command(sudoPath, "masscan", ip, "-p1-65535,U:1-65535", "-e", inter, "--rate="+rate)
	}
	// Interruption Handler
	terminator.InterruptMasscan(cmd)
	// Capture live progress
	var stdBuffer bytes.Buffer
	liveProgress := io.MultiWriter(os.Stdout, &stdBuffer)
	cmd.Stdout = liveProgress
	cmd.Stderr = liveProgress
	// Capture live results
	var output bytes.Buffer
	liveResults := io.MultiWriter(os.Stdout, &output)
	cmd.Stdout = liveResults
	// Executing the command with Run() to block until it finishes
	err := cmd.Run()
	if err != nil {
		log.Println(err)
	}
	// storing output
	capturedOutput := output.Bytes()
	return string(capturedOutput)
}

func ResultParser(data, protocol string) string {
	// Regex rules for extracting ports
	rules := regexp.MustCompile(`(\d+)/tcp|(\d+)/udp`)
	filteredString := rules.FindAllString(data, -1)
	// Extract Ports for the given protocol
	port := []string{}
	for i := range filteredString {
		if strings.HasSuffix(filteredString[i], "/"+protocol) {
			port = append(port, filteredString[i])
		}
	}
	// Format the ports in nmap format '-p1,2,3'
	singleLine := strings.Join(port, "")
	singleLine = strings.ReplaceAll(singleLine, "/"+protocol, ",")
	// trim last comma in port list
	if lastChar := len(singleLine) - 1; lastChar >= 0 && singleLine[lastChar] == ',' {
		singleLine = singleLine[:lastChar]
	}
	return singleLine
}
