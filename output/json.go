package output

import (
	"encoding/json"
	"os"

	"github.com/r4j3sh-com/triksha/core"
)

func WriteJSONReport(results []core.Result, path string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
