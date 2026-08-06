package renderers

import (
	"encoding/json"
	"io"

	"github.com/downorwhy/downorwhy/internal/core/types"
)

// JSON writes the report as indented JSON to w.
func JSON(w io.Writer, report *types.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}
