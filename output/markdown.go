package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/r4j3sh-com/triksha/core"
)

func WriteMarkdownReport(results []core.Result, path string) error {
	var sb strings.Builder
	sb.WriteString("# Triksha Recon Report\n\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("## Module: %s\n\n", r.ModuleName))
		for k, v := range r.Data {
			sb.WriteString(fmt.Sprintf("**%s:**\n", k))
			sb.WriteString("```\n")
			sb.WriteString(fmt.Sprintf("%v\n", v))
			sb.WriteString("```\n\n")
		}
	}
	return os.WriteFile(path, []byte(sb.String()), 0644)
}
