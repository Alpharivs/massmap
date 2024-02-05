package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Alpharivs/massmap/massScan"
	"github.com/Alpharivs/massmap/nmapScan"
	"github.com/theckman/yacspin"

	"github.com/fatih/color"
)

//go:embed banner.txt
var banner string

var (
	flInter  = flag.String("e", "tun0", "NIC for masscan")
	flTarget = flag.String("u", "", "Target IP (Required)")
	flRate   = flag.String("r", "500", "Rate for masscan")
	flFolder = flag.String("o", ".", "Folder to save nmap output without trailing '/'") // I will improve this function later
	flDocker = flag.Bool("docker", false, "Use a dockerized version of masscan.")
	warning  = color.RedString("[!]")
	arrows   = color.RedString("==>")
	wg       sync.WaitGroup
)

func createSpinner() (*yacspin.Spinner, error) {
	// Build the configuration
	cfg := yacspin.Config{
		Frequency:         100 * time.Millisecond,
		CharSet:           yacspin.CharSets[11],
		Suffix:            " ",
		SuffixAutoColon:   true,
		ColorAll:          false,
		Colors:            []string{"fgRed"},
		StopFailCharacter: "✗",
		StopFailColors:    []string{"fgRed"},
		StopFailMessage:   "failed",
	}

	s, err := yacspin.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to make spinner from struct: %w", err)
	}

	return s, nil
}

func main() {
	flag.Parse()
	// Required flags check
	if *flTarget == "" {
		fmt.Printf("%s Please specify the IP address, Usage: %s\n", warning, warning)
		flag.PrintDefaults()
		os.Exit(1)
	}
	// Initiate Spinner
	spinner, err := createSpinner()
	if err != nil {
		fmt.Printf("failed to make spinner from config struct: %v\n", err)
		os.Exit(1)
	}

	color.Blue(banner)
	color.Red("\n    LVX SIT - ALPHARIVS - MMDCCLXXVII \n\n")

	switch {
	// Target IP is IPv4
	case strings.Contains(*flTarget, "."):
		fmt.Printf("%s %s %s \n", warning, color.YellowString("Executing Masscan"), warning)
		result := massScan.Scan(*flTarget, *flInter, *flRate, *flDocker)
		//Print output if it was captured otherwise exit the program.
		if len(result) > 0 {
			fmt.Printf("\n%s %s \n\n%s\n", arrows, color.BlueString("Masscan Result:"), result)
		} else {
			color.Red("\n\r✗ Masscan was interrupted and no port was found")
			os.Exit(1)
		}
		tcpPorts, udpPorts := massScan.ResultParser(result)
		// Pass TCP and UDP or only TCP results to nmap
		if udpPorts != "" {
			spinner.Start()
			spinner.Message("Executing Nmap TCP and UDP scan")
			// Store and pass the masscan result into nmap TCP and UDP concurrent scans
			wg.Add(2)
			go nmapScan.Scan("-sS", tcpPorts, *flTarget, *flFolder, &wg, spinner)
			go nmapScan.Scan("-sU", udpPorts, *flTarget, *flFolder, &wg, spinner)
			wg.Wait()
			spinner.Stop()
		} else {
			spinner.Start()
			messages := color.YellowString("Executing Nmap TCP scan")
			spinner.Message(messages)
			// Store and pass the masscan result into nmap TCP scan
			wg.Add(1)
			go nmapScan.Scan("-sS", tcpPorts, *flTarget, *flFolder, &wg, spinner)
			wg.Wait()
			spinner.Stop()
		}
	// Target IP is IPv6
	case strings.Contains(*flTarget, ":"):
		spinner.Start()
		spinner.Message("IPv6 Detected executing Nmap IPv6 scan")
		// Execute Masscan
		nmapScan.Ipv6(*flTarget, *flFolder, spinner)
		spinner.Stop()
	}
}
