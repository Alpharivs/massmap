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
	flInter  = flag.String("e", "tun0", "NIC for Masscan")
	flTarget = flag.String("u", "", "Target IP (Required)")
	flRate   = flag.String("r", "500", "Rate for Masscan")
	flFolder = flag.String("o", ".", "Folder to save Nmap output without trailing '/'")
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
	color.Red("\n    LVX SIT - ALPHARIVS - MMXXII \n\n")

	switch {
	// Target IP is IPv4
	case strings.Contains(*flTarget, "."):
		fmt.Printf("%s %s %s \n", warning, color.YellowString("Executing Masscan"), warning)
		//Print the output of masscan if any
		result := massScan.Scan(*flTarget, *flInter, *flRate)
		if len(result) > 0 {
			fmt.Printf("\n%s %s \n\n%s\n", arrows, color.BlueString("Masscan Result:"), result)
		}
		// Pass TCP and UDP or only TCP results to nmap
		if strings.Contains(result, "/udp") {
			// Run Spinner
			spinner.Start()
			spinner.Message("Executing Nmap TCP and UDP scan")
			// Store and pass the masscan result into nmap TCP and UDP concurrent scans
			openPorts := massScan.ResultParser(result, "tcp")
			wg.Add(1)
			go nmapScan.Scan("-sS", openPorts, *flTarget, *flFolder, &wg, spinner)
			openPorts = massScan.ResultParser(result, "udp")
			wg.Add(1)
			go nmapScan.Scan("-sU", openPorts, *flTarget, *flFolder, &wg, spinner)
			wg.Wait()
			spinner.Stop()
		} else {
			// Run Spinner
			spinner.Start()
			messages := color.YellowString("Executing Nmap TCP scan")
			spinner.Message(messages)
			// Store and pass the masscan result into nmap TCP scan
			openPorts := massScan.ResultParser(result, "tcp")
			wg.Add(1)
			go nmapScan.Scan("-sS", openPorts, *flTarget, *flFolder, &wg, spinner)
			wg.Wait()
			spinner.Stop()
		}
	// Target IP is IPv6
	case strings.Contains(*flTarget, ":"):
		// Run Spinner
		spinner.Start()
		spinner.Message("IPv6 Detected executing Nmap IPv6 scan")
		// Execute Masscan
		nmapScan.Ipv6(*flTarget, *flFolder, spinner)
		spinner.Stop()
	}
}
