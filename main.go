package main

import (
	"os"

	"github.com/darvid/nessusbeat/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
