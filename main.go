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
	"github.com/fatih/color"
	"github.com/theckman/yacspin"
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
	color.Red("\n   LVX SIT - ALPHARIVS - MMDCCLXXVII \n\n")

	switch {
	// Target IP is IPv4
	case strings.Contains(*flTarget, "."):
		fmt.Printf("%s %s %s \n", warning, color.YellowString("Executing Masscan"), warning)
		// Run masscan
		result := massScan.Scan(*flTarget, *flInter, *flRate, *flDocker)
		// Separate and store TCP and UDP results
		tcpPorts, udpPorts := massScan.ResultParser(result)
		// Check whether both UDP and TCP are present or if only one of both is present.
		if tcpPorts != "" && udpPorts != "" {
			spinner.Start()
			message := color.YellowString("Executing Nmap TCP and UDP scan")
			spinner.Message(message)
			defer spinner.Stop()
			// Create buffered channels to receive output and prevent deadlock.
			tcpOutput := make(chan []byte, 1)
			udpOutput := make(chan []byte, 1)
			/* Changed to anonymous routine from 'go nmapScan.Scan("-sU", udpPorts, *flTarget, *flFolder, &wg, spinner)'
			if only tcp is discovered there's no need for Scan to run with concurrency and the solution was using the wg.Done() in an anon. routine */
			wg.Add(2)
			go func() {
				defer wg.Done()
				output := nmapScan.Scan("-sS", tcpPorts, *flTarget, spinner)
				fmt.Print("\r\033[K")
				fmt.Println("\r[!] TCP scan completed.")
				// Send output to channel
				tcpOutput <- output
			}()
			go func() {
				defer wg.Done()
				output := nmapScan.Scan("-sU", udpPorts, *flTarget, spinner)
				fmt.Print("\r\033[K")
				fmt.Println("\r[!] UDP scan completed.")
				// Send output to channel
				udpOutput <- output
			}()
			wg.Wait()
			// Receive output from channel and pass it to the EndScan function to ensure that TCP and UDP results will be printed when both routines finish.
			tcpResult := <-tcpOutput
			udpResult := <-udpOutput
			close(tcpOutput)
			close(udpOutput)

			nmapScan.EndScan("TCP", *flFolder, "/nmap.out", tcpResult)
			nmapScan.EndScan("UDP", *flFolder, "/nmap_udp.out", udpResult)
		} else if tcpPorts != "" {
			spinner.Start()
			message := color.YellowString("Executing Nmap TCP scan")
			spinner.Message(message)
			defer spinner.Stop()

			tcpResult := nmapScan.Scan("-sS", tcpPorts, *flTarget, spinner)
			nmapScan.EndScan("TCP", *flFolder, "/nmap.out", tcpResult)
		} else {
			spinner.Start()
			message := color.YellowString("Executing Nmap UDP scan")
			spinner.Message(message)
			defer spinner.Stop()

			udpResult := nmapScan.Scan("-sU", udpPorts, *flTarget, spinner)
			nmapScan.EndScan("UDP", *flFolder, "/nmap_udp.out", udpResult)
		}
	// Target IP is IPv6
	case strings.Contains(*flTarget, ":"):
		spinner.Start()
		message := color.YellowString("IPv6 Detected executing Nmap IPv6 scan")
		spinner.Message(message)
		defer spinner.Stop()

		ip6Result := nmapScan.Ipv6(*flTarget, spinner)
		nmapScan.EndScan("IPv6", *flFolder, "/nmap_v6.out", ip6Result)
	}
}
