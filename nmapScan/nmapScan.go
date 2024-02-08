package nmapScan

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/theckman/yacspin"
)

func interrupt(spinner *yacspin.Spinner) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		/* ensure we stop the spinner before exiting, otherwise cursor will remain
		   hidden and terminal will require a `reset` */
		spinner.StopFailMessage("interrupted")
		_ = spinner.StopFail()
		os.Exit(0)
	}()
}

func EndScan(protocol, folder, file string, content []byte) {
	arrows := color.RedString("==>")
	message := color.BlueString("Nmap " + protocol + "Scan Result:")
	// Print Result Message and Result
	fmt.Printf("\n\n%s %s\n\n", arrows, message)
	fmt.Println(string(content))
	// Save Result to File
	outFile := folder + file
	os.WriteFile(outFile, content, 0644)
	fmt.Printf("%s %s %s\n\n", arrows, color.YellowString("Results Saved to:"), outFile)
}

func Scan(protocol, openPorts, ip string, spinner *yacspin.Spinner) []byte {
	interrupt(spinner)
	cmd := exec.Command("sudo", "nmap", "-p"+openPorts, protocol, "-sC", "-sV", "-Pn", ip, "-n")
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	return out
}

func Ipv6(ip string, spinner *yacspin.Spinner) []byte {
	interrupt(spinner)
	cmd := exec.Command("sudo", "nmap", "-6", "-sC", "-sV", ip)
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	return out
}
