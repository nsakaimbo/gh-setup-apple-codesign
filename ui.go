package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ANSI color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
)

// logStep prints a colored step indicator
func logStep(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s▶ %s%s\n", colorCyan, msg, colorReset)
}

// logInfo prints an informational message with indentation
func logInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s\n", msg)
}

// logWarning prints a warning message in yellow
func logWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s⚠️  %s%s\n", colorYellow, msg, colorReset)
}

// logError prints an error message in red to stderr
func logError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s✖ Error: %s%s\n", colorRed, msg, colorReset)
}

// promptForInput prompts the user for input if an environment variable is not set
func promptForInput(reader *bufio.Reader, envName, prompt string) string {
	fmt.Printf("\n%s%s is not set.%s\n", colorYellow, envName, colorReset)
	fmt.Printf("%s: ", prompt)

	input, err := reader.ReadString('\n')
	if err != nil {
		logError("Error reading input: %s", err)
		os.Exit(1)
	}
	input = strings.TrimSpace(input)

	if input == "" {
		logError("%s is required", envName)
		os.Exit(1)
	}

	return input
}
