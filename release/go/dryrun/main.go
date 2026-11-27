// Command dryrun is the program that the release dry run builds from the
// packed rustleaks-go modules. It scans one synthetic AWS access key and
// fails unless the engine reports it.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/joshgarnett/rustleaks-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dryrun:", err)
		os.Exit(1)
	}
}

func run() error {
	engine, err := rustleaks.New()
	if err != nil {
		return err
	}
	defer engine.Close()
	// The key is built at run time so the repository self-scan does not
	// report this file.
	input := "string AWSToken = \"AKIA" + "LALEMEL33243OLIB\";\n"
	findings, err := engine.ScanString(context.Background(), input)
	if err != nil {
		return err
	}
	for _, finding := range findings {
		if finding.RuleID == "aws-access-token" {
			fmt.Printf("found %s on line %d with %d rules loaded\n", finding.RuleID, finding.StartLine, len(engine.Rules()))
			return nil
		}
	}
	return fmt.Errorf("no aws-access-token finding in %d findings", len(findings))
}
