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

func ResultParser(data string) (tcpResult string, udpResult string) {
	// Regex rules for extracting ports
	rules := regexp.MustCompile(`(\d+)/tcp|(\d+)/udp`)
	filteredString := rules.FindAllString(data, -1)
	// Extract Ports for the given protocol
	var tcpPorts, udpPorts []string

	for _, port := range filteredString {
		if strings.HasSuffix(port, "/tcp") {
			tcpPorts = append(tcpPorts, strings.TrimSuffix(port, "/tcp"))
		} else if strings.HasSuffix(port, "/udp") {
			udpPorts = append(udpPorts, strings.TrimSuffix(port, "/udp"))
		}
	}
	tcpResult = strings.Join(tcpPorts, ",")
	udpResult = strings.Join(udpPorts, ",")

	tcpResult = strings.TrimSuffix(tcpResult, ",")
	udpResult = strings.TrimSuffix(udpResult, ",")

	return tcpResult, udpResult
}
