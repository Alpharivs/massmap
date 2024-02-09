package nmapScan

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/theckman/yacspin"
)

var (
	arrows      = color.RedString("==>")
	interrupted bool
)

func interrupt(cmd *exec.Cmd, spinner *yacspin.Spinner) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		interrupted = true
		cmd.Process.Kill()
		/* ensure we stop the spinner before exiting, otherwise cursor will remain
		   hidden and terminal will require a `reset` */
		spinner.StopFailMessage("interrupted")
		_ = spinner.StopFail()
		os.Exit(1)
	}()
}

func saveOutput(content []byte, outputFlag, extension string) {
	resultMessage := color.YellowString("Results Saved to:")
	// Check if the value passed in the flag is just a directory without filename.
	if strings.HasSuffix(outputFlag, "/") {
		outputFlag = outputFlag + "nmap"
	}
	// Save output with extension.
	outFile := outputFlag + extension
	err := os.WriteFile(outFile, content, 0644)
	if err != nil {
		log.Printf("error saving output: %v", err)
	}

	fmt.Printf("%s %s %s\n\n", arrows, resultMessage, outFile)
}

func EndScan(protocol, outputFlag, extension string, content []byte) {
	startMessage := color.BlueString("Nmap " + protocol + "Scan Result:")
	// Print Result Message and Result
	fmt.Printf("\n\n%s %s\n\n", arrows, startMessage)
	fmt.Println(string(content))
	// Save Result to File
	saveOutput(content, outputFlag, extension)
}

func Scan(protocol, openPorts, ip string, spinner *yacspin.Spinner) []byte {
	cmd := exec.Command("sudo", "nmap", "-p"+openPorts, protocol, "-sC", "-sV", "-Pn", ip, "-n")
	// Interruption Handler
	interrupted = false
	interrupt(cmd, spinner)
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil && !interrupted {
		log.Fatalf("error executing nmap: %v", err)
	}
	return out
}

func Ipv6(ip string, spinner *yacspin.Spinner) []byte {
	cmd := exec.Command("sudo", "nmap", "-6", "-sC", "-sV", ip)
	interrupt(cmd, spinner)
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("error executing nmap: %v", err)
	}
	return out
}
