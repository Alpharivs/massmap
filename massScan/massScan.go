package massScan

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Alpharivs/massmap/terminator"
)

func Scan(ip, inter, rate string) string {
	// masscanCmd := fmt.Sprintf("sudo docker run -i --network host --rm adarnimrod/masscan -p1-65535,U:1-65535 %s -e %s --rate=%s --wait=5", ip, inter, rate)

	// Using exec.Command directly with masscan didn't work
	masscanCmd := fmt.Sprintf("sudo masscan %s -p1-10000 -e %s --rate=%s --wait=5", ip, inter, rate)

	cmd := exec.Command("bash", "-c", masscanCmd)
	terminator.InterruptMasscan(cmd)
	// a : setup for stdout capture (not capturing stderr)
	var stdBuffer bytes.Buffer
	live := io.MultiWriter(os.Stdout, &stdBuffer)
	cmd.Stdout = live
	cmd.Stderr = live
	// b : capturing stdout //Could it be improved with combinedoutput()?
	output := &bytes.Buffer{}
	cmd.Stdout = output
	// Executing the command with run to block untill it finishes
	err := cmd.Run()
	if err != nil {
		log.Fatalln(err)
	}
	// a : Print live output
	log.Println(stdBuffer.String())
	// b : storing output for parsing
	capturedOutput := output.Bytes()
	return string(capturedOutput)

}

func ResultParser(data, protocol string) string {
	// Regex rules for extracting ports
	rules := regexp.MustCompile(`(\d+)/tcp|(\d+)/udp`)
	filteredString := rules.FindAllString(data, -1)
	// Extract Ports for the given protocol
	port := []string{}
	for i := range filteredString {
		if strings.HasSuffix(filteredString[i], "/"+protocol) {
			port = append(port, filteredString[i])
		}
	}
	// Format the ports in nmap format '-p1,2,3'
	singleLine := strings.Join(port, "")
	singleLine = strings.ReplaceAll(singleLine, "/"+protocol, ",")
	// trim last comma in port list
	if lastChar := len(singleLine) - 1; lastChar >= 0 && singleLine[lastChar] == ',' {
		singleLine = singleLine[:lastChar]
	}
	return singleLine
}
