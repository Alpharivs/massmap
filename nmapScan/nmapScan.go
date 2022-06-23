package nmapScan

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/Alpharivs/massmap/terminator"
	"github.com/fatih/color"
	"github.com/theckman/yacspin"
)

func endScan(protocol, folder, file string, content []byte) {
	arrows := color.RedString("==>")
	message := color.BlueString("Nmap " + protocol + "Scan Result:")
	// Print Reult Message and Result
	fmt.Printf("\n\n%s %s\n\n", arrows, message)
	fmt.Println(string(content))
	// Save Result to File
	outfile := folder + file
	os.WriteFile(outfile, content, 0644)
	fmt.Printf("%s %s %s\n\n", arrows, color.YellowString("Results Saved to:"), outfile)
}

func Scan(protocol, openPorts, ip, folder string, wg *sync.WaitGroup, spinner *yacspin.Spinner) {
	defer wg.Done()
	terminator.Interrupt(spinner)
	cmd := exec.Command("sudo", "nmap", "-p"+openPorts, protocol, "-sC", "-sV", "-Pn", ip, "-n")
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	// Print and save Result
	if protocol == "-sS" {
		endScan("TCP", folder, "/nmap.out", out)
	} else {
		endScan("UDP", folder, "/nmap_udp.out", out)
	}
}

func Ipv6(ip, folder string, spinner *yacspin.Spinner) {
	terminator.Interrupt(spinner)
	cmd := exec.Command("sudo", "nmap", "-6", "-sC", "-sV", ip)
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	// Print and save Result
	endScan("IPv6", folder, "/nmap_v6.out", out)
}
