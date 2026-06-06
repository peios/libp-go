package main

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

// TestAnalyzer runs the analyzer over testdata/src/consumer, whose
// `// want` comments mark every line the analyzer must flag.
func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), analyzer, "consumer")
}

func TestIsLibpGoInternal(t *testing.T) {
	cases := map[string]bool{
		"github.com/peios/libp-go":       true,
		"github.com/peios/libp-go/token": true,
		"github.com/peios/libp-go/sd":    true,
		"github.com/peios/loregd/store":  false,
		"github.com/peios/libp-go-ish/x": false,
		"os":                             false,
	}
	for path, want := range cases {
		if got := isLibpGoInternal(path); got != want {
			t.Errorf("isLibpGoInternal(%q) = %v, want %v", path, got, want)
		}
	}
}
