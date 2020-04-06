// +build !linux

package edge

import (
	"os/exec"
)

// We do not need to do anything to cause
// child processes to die with us under darwin
func commandFix(c *exec.Cmd) {
}
