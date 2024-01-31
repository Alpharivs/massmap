package terminator

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/theckman/yacspin"
)

func InterruptMasscan(cmd *exec.Cmd) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cmd.Process.Kill()
		//generating a delay bewteen killing masscan and calling cleanupto give time for file generation
		time.Sleep(1 * time.Second)
		// cleanup paused.conf
		_ = os.Remove("paused.conf")
	}()
}

func Interrupt(spinner *yacspin.Spinner) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		/* ensure we stop the spinner before exiting, otherwise cursor will remain
		   hidden and terminal will require a `reset` */
		spinner.StopFailMessage("interrupted")
		_ = spinner.StopFail()
		os.Exit(0)
	}()
}
