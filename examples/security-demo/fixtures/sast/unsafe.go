// This file is scanner training data. It is not compiled or deployed.
package fixture

import "os/exec"

func unsafeShell(userInput string) *exec.Cmd {
	return exec.Command("sh", "-c", userInput)
}
