package massScan

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
)

// edit sudo path if necessary
var (
	sudoPath    = "/usr/bin/sudo"
	interrupted bool
)

func interruptMasscan(cmd *exec.Cmd) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		interrupted = true
		cmd.Process.Kill()
		color.Red("\n\r✗ Interrupted, piping results to Nmap")
		// Generating a delay between killing masscan and cleaning up to give time for file generation
		time.Sleep(1 * time.Second)
		// cleanup paused.conf
		_ = os.Remove("paused.conf")
	}()
}

func Scan(ip, inter, rate string, docker bool) string {
	arrows := color.RedString("==>")
	resultMessage := color.BlueString("Masscan Result:")

	var cmd *exec.Cmd
	if docker {
		cmd = exec.Command(sudoPath, "docker", "run", "-i", "--network", "host", "--rm", "adarnimrod/masscan", "-p1-65535,U:1-65535", ip, "-e", inter, "--rate="+rate, "--wait=5")
	} else {
		cmd = exec.Command(sudoPath, "masscan", ip, "-p1-65535,U:1-65535", "-e", inter, "--rate="+rate)
	}
	// Interruption Handler
	interrupted = false
	interruptMasscan(cmd)
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
	if err != nil && !interrupted {
		log.Fatalf("error executing masscan: %v", err)
	}
	// storing output
	capturedOutput := output.Bytes()
	// Checking if output is empty
	if len(capturedOutput) > 0 {
		fmt.Printf("\n%s %s \n\n%s\n", arrows, resultMessage, capturedOutput)
	} else {
		color.Red("\n\r✗ No port was found")
		os.Exit(0)
	}

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
