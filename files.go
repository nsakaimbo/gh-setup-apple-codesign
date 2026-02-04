package main

import (
	"os"
	"path/filepath"
	"strings"
)

// expandPath expands ~ to the user's home directory
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(homeDir, path[2:])
	}
	return path
}

// artifactsExist checks if the output directory contains any artifacts
func artifactsExist(dir string) bool {
	files := []string{
		privateKeyFilename,
		p12BundleFilename,
		pemBundleFilename,
	}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}
