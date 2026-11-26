package rustleaks_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	rustleaks "github.com/joshgarnett/rustleaks-go"
)

// The examples build key-shaped values at run time, so that the source
// holds no complete key. The values are synthetic test data.

func Example() {
	engine, err := rustleaks.New()
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	input := "string AWSToken = \"" + "AKIA" + "LALEMEL33243OLIB" + "\";\n"
	findings, err := engine.ScanString(context.Background(), input, rustleaks.WithPath("src/app.go"))
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range findings {
		// Printing a finding shows the rule and position, not the secret.
		fmt.Println(f)
	}
	// Output:
	// {RuleID:aws-access-token Path:src/app.go StartLine:1 EndLine:1 StartColumn:20 EndColumn:39}
}

func ExampleWithConfig() {
	config := []byte(`
[extend]
useDefault = true

[[rules]]
id = "example-ticket"
description = "Example ticket token"
regex = '''TICKET-([0-9]{6})'''
secretGroup = 1
keywords = ["ticket-"]
`)
	engine, err := rustleaks.New(rustleaks.WithConfig(config))
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	findings, err := engine.ScanString(context.Background(), "first line\nnext TICKET-123456 here\n")
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range findings {
		fmt.Println(f.RuleID, f.StartLine, f.SecretRange.Start, f.SecretRange.End)
	}
	// Output:
	// example-ticket 2 23 29
}

func ExampleWithRules() {
	engine, err := rustleaks.New(rustleaks.WithRules("aws-access-token"))
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	for _, rule := range engine.Rules() {
		fmt.Println(rule.ID)
	}

	_, err = rustleaks.New(rustleaks.WithRules("no-such-rule"))
	var configErr *rustleaks.ConfigError
	fmt.Println(errors.As(err, &configErr), configErr.Kind)
	// Output:
	// aws-access-token
	// true rule selection
}

func ExampleEngine_ScanBytes_deadline() {
	engine, err := rustleaks.New()
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	// Set a deadline for untrusted input.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	findings, err := engine.ScanBytes(ctx, []byte("nothing to find here\n"))
	if errors.Is(err, context.DeadlineExceeded) {
		fmt.Println("the scan ran out of time")
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(findings), "findings")
	// Output:
	// 0 findings
}

func ExampleFinding_Redacted() {
	f := rustleaks.Finding{RuleID: "example", Secret: "abcdefgh", Match: "key=abcdefgh", Line: "key=abcdefgh"}
	masked := f.Redacted(50)
	fmt.Println(masked.Secret, masked.Match)
	fmt.Println(f.Redacted(100).Line)
	// Output:
	// abcd... key=abcd...
	// key=REDACTED
}

func ExampleWithAllowComments() {
	config := []byte(`
[[rules]]
id = "example-ticket"
regex = '''TICKET-[0-9]{6}'''
keywords = ["ticket-"]
`)
	// Content that other people write can carry allow comments, so do not
	// honor them there.
	engine, err := rustleaks.New(rustleaks.WithConfig(config), rustleaks.WithAllowComments(false))
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	findings, err := engine.ScanString(context.Background(), "TICKET-123456 # rustleaks:allow\n")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(findings))
	// Output:
	// 1
}
