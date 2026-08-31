// M23 Phase 2: interprocedural taint for Go. A source-like parameter that
// reaches a command sink (exec.Command) is BHF-304 (proven flow), distinct from
// the BHF-404 shell-literal heuristic. These use exec.Command WITHOUT a shell
// literal so only the taint engine fires (no BHF-404 overlap), isolating BHF-304.
package p

import (
	"log"
	"os/exec"
)

// Direct: a tainted source parameter reaches the sink in the same function.
func run(userInput string) {
	exec.Command(userInput) // EXPECT BHF-304
}

// Interprocedural: a source flows through a project-local call to the sink.
func dispatch(userQuery string) {
	forward(userQuery)
}

func forward(a string) {
	exec.Command(a) // EXPECT BHF-304
}

// Sanitized before the sink — taint is cleared, so nothing must fire here.
func clean(userPath string) {
	v := sanitize(userPath)
	exec.Command(v)
}

func logUser(userInput string) {
	log.Printf("%s", userInput) // EXPECT BHF-544
	log.Print("fixed")
}
