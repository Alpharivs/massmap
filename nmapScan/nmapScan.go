package nmapScan

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/fatih/color"
)

var arrows string = color.RedString("==>")

func Ipv4TCP(openPorts, ip, folder string, wg *sync.WaitGroup) {
	defer wg.Done()
	cmd := exec.Command("sudo", "nmap", "-p"+openPorts, "-sC", "-sV", "-Pn", ip, "-n")
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("\n%s %s\n\n", arrows, color.BlueString("Nmap TCP Scan Result:"))
	color.Cyan(string(out))
	// Write result to file
	os.WriteFile(folder+"/nmap.out", out, 0644)
}

func Ipv4UDP(openPorts, ip, folder string, wg *sync.WaitGroup) {
	defer wg.Done()
	cmd := exec.Command("sudo", "nmap", "-p"+openPorts, "-sU", "-sC", "-sV", "-Pn", ip, "-n")
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("\n%s %s\n\n", arrows, color.BlueString("Nmap UDP Scan Result:"))
	color.Cyan(string(out))
	// Write result to file
	os.WriteFile(folder+"/nmap_udp.out", out, 0644)
}

func Ipv6(ip, folder string) {
	cmd := exec.Command("sudo", "nmap", "-6", "-sC", "-sV", ip)
	// Capture output
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("\n%s %s\n\n", arrows, color.BlueString("Nmap IPv6 Scan Result:"))
	color.Cyan(string(out))
	// Write result to file
	os.WriteFile(folder+"/nmap_v6.out", out, 0644)
}
