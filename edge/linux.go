// +build linux

package edge

import (
	"os/exec"
	"syscall"
)

func commandFix(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
}
