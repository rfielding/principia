// +build linux

package edge

import (
	"os/exec"
	"syscall"
)

// Under Linux, we have to set this flag for child processes to die with the parent,
// and the Go code itself is not portable from Linux to OSX
func commandFix(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
}
