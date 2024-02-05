package nmapScan

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/Alpharivs/massmap/terminator"
	"github.com/fatih/color"
	"github.com/theckman/yacspin"
)

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
	terminator.Interrupt(spinner)
	cmd := exec.Command("sudo", "nmap", "-p"+openPorts, protocol, "-sC", "-sV", "-Pn", ip, "-n")
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	return out
}

func Ipv6(ip string, spinner *yacspin.Spinner) []byte {
	terminator.Interrupt(spinner)
	cmd := exec.Command("sudo", "nmap", "-6", "-sC", "-sV", ip)
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	return out
}
