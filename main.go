package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/Alpharivs/massmap/massScan"
	"github.com/Alpharivs/massmap/nmapScan"
	"github.com/Alpharivs/massmap/terminator"

	"github.com/fatih/color"
)

//go:embed banner.txt
var banner string

var (
	flInter  = flag.String("e", "tun0", "NIC for Masscan")
	flTarget = flag.String("u", "", "Target IP (Required)")
	flRate   = flag.String("r", "500", "Rate for Masscan")
	flFolder = flag.String("o", ".", "Folder to save Nmap output without trailing '/'")
	warning  = color.RedString("[!]")
	arrows   = color.RedString("==>")
	wg       sync.WaitGroup
)

func main() {
	flag.Parse()
	// Required flags check
	if *flTarget == "" {
		fmt.Printf("%s Please specify the IP address, Usage: %s\n", warning, warning)
		flag.PrintDefaults()
		os.Exit(1)
	}
	// Bootleg way of executing a different interrupt function for masscan as interrupting masscan involves cleanup (paused.cnf)
	if strings.Contains(*flTarget, ":") {
		terminator.Interrupt()
	}

	color.Blue(banner + "\n\n  LVX SIT - ALPHARIVS - MMXXII \n\n")

	switch {
	// Target IP isIPv4
	case strings.Contains(*flTarget, "."):
		log.Printf("%s %s %s \n", warning, color.BlueString("Executing Masscan"), warning)
		result := massScan.Scan(*flTarget, *flInter, *flRate)
		//Print the output of masscan if any
		if len(result) > 0 {
			fmt.Printf("\n%s %s \n\n%s\n", arrows, color.BlueString("Masscan Result:"), color.CyanString(result))
		}
		// Pass TCP and UDP or only TCP results to nmap
		log.Printf("%s %s %s\n", warning, color.BlueString("Executing Nmap scan"), warning)
		if strings.Contains(result, "/udp") {
			openPorts := massScan.ResultParser(result, "tcp")
			wg.Add(1)
			go nmapScan.Ipv4TCP(openPorts, *flTarget, *flFolder, &wg)
			openPorts = massScan.ResultParser(result, "udp")
			wg.Add(1)
			go nmapScan.Ipv4UDP(openPorts, *flTarget, *flFolder, &wg)
			wg.Wait()
		} else {
			openPorts := massScan.ResultParser(result, "tcp")
			wg.Add(1)
			go nmapScan.Ipv4TCP(openPorts, *flTarget, *flFolder, &wg)
			wg.Wait()
		}
	// Target IP is IPv6
	case strings.Contains(*flTarget, ":"):
		log.Printf("%s %s %s\n", warning, color.BlueString("IPv6 Detected executing Nmap IPv6 scan"), warning)
		nmapScan.Ipv6(*flTarget, *flFolder)
	}
}
