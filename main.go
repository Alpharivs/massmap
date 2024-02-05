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
	// Banner
	color.Blue(banner)
	color.Red("\n    LVX SIT - ALPHARIVS - MMDCCLXXVII \n\n")

	switch {
	// Target IP is IPv4
	case strings.Contains(*flTarget, "."):
		fmt.Printf("%s %s %s \n", warning, color.YellowString("Executing Masscan"), warning)
		// Run masscan and print output if it was captured otherwise exit the program.
		result := massScan.Scan(*flTarget, *flInter, *flRate, *flDocker)
		// Separate and store TCP and UDP results
		tcpPorts, udpPorts := massScan.ResultParser(result)
		// Check if UDP scanning is necessary else run only TCP scan.
		if udpPorts != "" {
			spinner.Start()
			message := color.YellowString("Executing Nmap TCP and UDP scan")
			spinner.Message(message)
			defer spinner.Stop()
			// Changed to anonymous routine from 'go nmapScan.Scan("-sU", udpPorts, *flTarget, *flFolder, &wg, spinner)'
			// if only tcp is discovered there's no need for Scan to run with concurrency and the solution was using the wg.Done() in an anon. routine
			wg.Add(2)
			go func() {
				defer wg.Done()
				nmapScan.Scan("-sS", tcpPorts, *flTarget, *flFolder, spinner)
			}()
			go func() {
				defer wg.Done()
				nmapScan.Scan("-sU", udpPorts, *flTarget, *flFolder, spinner)
			}()
			wg.Wait()
		} else {
			spinner.Start()
			message := color.YellowString("Executing Nmap TCP scan")
			spinner.Message(message)
			defer spinner.Stop()

			nmapScan.Scan("-sS", tcpPorts, *flTarget, *flFolder, spinner)
		}
	// Target IP is IPv6
	case strings.Contains(*flTarget, ":"):
		spinner.Start()
		message := color.YellowString("IPv6 Detected executing Nmap IPv6 scan")
		spinner.Message(message)
		defer spinner.Stop()

		nmapScan.Ipv6(*flTarget, *flFolder, spinner)
	}
}
