package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunAnalyze_OutputFileCloseWarningDoesNotPanic(t *testing.T) {
	// This test is intentionally shallow: it asserts that the CLI can write to an
	// output path and returns a non-error exit code. It also exercises the output
	// file close warning path defensively (without requiring a forced close error).
	//
	// Note: we cannot reliably force os.File.Close() to error in a portable unit
	// test, so this focuses on ensuring the deferred close wrapper is safe.
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.json")

	// Use bundled example log to ensure deterministic parse.
	args := []string{"--format", "json", "--output", outPath, "../../examples/linux-auth.log"}
	code := runAnalyze(args)
	if code != 0 && code != 1 { // 1 is a valid "suspicious" exit
		t.Fatalf("expected exit code 0 or 1, got %d", code)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected output file to exist: %v", err)
	}
}
