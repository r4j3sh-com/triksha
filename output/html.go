package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/r4j3sh-com/triksha/core"
)

func WriteHTMLReport(results []core.Result, path string) error {
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Triksha Recon Report</title></head><body>")
	sb.WriteString("<h1>Triksha Recon Report</h1>")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("<h2>Module: %s</h2>", r.ModuleName))
		for k, v := range r.Data {
			sb.WriteString(fmt.Sprintf("<strong>%s:</strong><pre>%v</pre>", k, v))
		}
	}
	sb.WriteString("</body></html>")
	return os.WriteFile(path, []byte(sb.String()), 0644)
}
