package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
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

// Flags
var (
	flInter  = flag.String("e", "tun0", "NIC for masscan")
	flTarget = flag.String("u", "", "Target IP (Required)")
	flRate   = flag.String("r", "500", "Rate for masscan")
	flFolder = flag.String("o", ".", "Folder to save nmap output without trailing '/'") // I will improve this function later
	flDocker = flag.Bool("docker", false, "Use a dockerized version of masscan.")
	warning  = color.RedString("[!]")
)

// Constants
const (
	defaultNmapPath = "/nmap.out"
	defaultUdpPath  = "/nmap_upd.out"
	defaultIpv6Path = "/nmap_6.out"
	tcpFlag         = "-sS"
	updFlag         = "-sU"
	tcpString       = "TCP"
	udpString       = "UDP"
	iPv6String      = "IPv6"
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

	return yacspin.New(cfg)
}

func executeScan(spinner *yacspin.Spinner) {
	message := color.YellowString("Executing masscan")
	fmt.Printf("%s %s %s \n", warning, message, warning)
	// Run masscan
	result := massScan.Scan(*flTarget, *flInter, *flRate, *flDocker)
	// Separate and store TCP and UDP results
	tcpPorts, udpPorts := massScan.ResultParser(result)
	// Check whether both UDP and TCP are present or if only one of both is present.
	if tcpPorts != "" && udpPorts != "" {
		executeConcurrentScan(spinner, tcpPorts, udpPorts)
	} else if tcpPorts != "" {
		executeSingleScan(spinner, tcpPorts, tcpFlag, tcpString, defaultNmapPath)
	} else {
		executeSingleScan(spinner, udpPorts, updFlag, udpString, defaultUdpPath)
	}
}

func executeConcurrentScan(spinner *yacspin.Spinner, tcpPorts, udpPorts string) {
	spinner.Start()
	message := color.YellowString("Executing nmap TCP and UDP scan")
	spinner.Message(message)
	defer spinner.Stop()
	// Initialize wait group
	wg := sync.WaitGroup{}
	wg.Add(2)
	// Create buffered channels to receive output and prevent deadlock.
	tcpOutput := make(chan []byte, 1)
	udpOutput := make(chan []byte, 1)
	/* Changed to anonymous routine from 'go nmapScan.Scan("-sU", udpPorts, *flTarget, *flFolder, &wg, spinner)'
	if only tcp is discovered there's no need for Scan to run with concurrency and the solution was using the wg.Done() in an anon. routine */
	go func() {
		defer wg.Done()
		output := nmapScan.Scan(tcpFlag, tcpPorts, *flTarget, spinner)
		// Clear terminal
		clearTerminal(tcpString)
		// Send output to channel
		tcpOutput <- output
	}()

	go func() {
		defer wg.Done()
		output := nmapScan.Scan(updFlag, udpPorts, *flTarget, spinner)
		// Clear terminal
		clearTerminal(udpString)
		// Send output to channel
		udpOutput <- output
	}()

	wg.Wait()
	// Receive output from channel and pass it to the EndScan function to ensure that TCP and UDP results will be printed when both routines finish.
	tcpResult := <-tcpOutput
	udpResult := <-udpOutput
	// Close channels
	close(tcpOutput)
	close(udpOutput)

	nmapScan.EndScan(tcpString, *flFolder, defaultNmapPath, tcpResult)
	nmapScan.EndScan(udpString, *flFolder, defaultUdpPath, udpResult)
}

func clearTerminal(protocol string) {
	fmt.Print("\r\033[K")
	fmt.Printf("\r[!] %s scan completed.\n", protocol)
}

func executeSingleScan(spinner *yacspin.Spinner, ports, nmapFlag, scanType, fileName string) {
	spinner.Start()
	defer spinner.Stop()

	message := color.YellowString("Executing nmap %s scan", scanType)
	spinner.Message(message)

	result := nmapScan.Scan(nmapFlag, ports, *flTarget, spinner)
	nmapScan.EndScan(scanType, *flFolder, fileName, result)
}

func executeIPv6Scan(spinner *yacspin.Spinner) {
	spinner.Start()
	defer spinner.Stop()

	message := color.YellowString("IPv6 Detected executing nmap IPv6 scan")
	spinner.Message(message)

	ip6Result := nmapScan.Ipv6(*flTarget, spinner)
	nmapScan.EndScan(iPv6String, *flFolder, defaultIpv6Path, ip6Result)
}

func main() {
	// Required flags check
	flag.Parse()
	if *flTarget == "" {
		fmt.Printf("%s please specify the IP address, usage: %s\n", warning, warning)
		flag.PrintDefaults()
		os.Exit(1)
	}
	// Initiate Spinner
	spinner, err := createSpinner()
	if err != nil {
		log.Fatalf("failed to make spinner from config struct: %v\n", err)
	}
	defer spinner.Stop()
	// Banner
	color.Blue(banner)
	color.Red("\n   LVX SIT - ALPHARIVS - MMDCCLXXVII \n\n")
	// Detect if address is IPv4 or IPv6
	switch {
	case strings.Contains(*flTarget, "."):
		executeScan(spinner)
	case strings.Contains(*flTarget, ":"):
		executeIPv6Scan(spinner)
	}
}
