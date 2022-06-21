package terminator

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
)

//clean paused.conf generated when interrupting masscan
func cleanup() {
	color.Red("\r- Cleaning Up -")
	_ = os.Remove("paused.conf")
	color.Red("- EXTERMINATVS PROTOCOL ACTIVATED -")
	color.Red("- 487964726120446f6d696e617475730a -")
}

func InterruptMasscan(cmd *exec.Cmd) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		//generating a delay bewteen killing masscan and calling cleanupto give time for file generation
		cmd.Process.Kill()
		time.Sleep(1 * time.Second)
		cleanup()
		os.Exit(0)
	}()
}

func Interrupt() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		color.Red("\r- EXTERMINATVS PROTOCOL ACTIVATED -")
		color.Red("\r- 487964726120446f6d696e617475730a -")
		os.Exit(0)
	}()
}
