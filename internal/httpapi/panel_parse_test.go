package httpapi

import (
	"html/template"
	"io/fs"
	"testing"

	"github.com/atelie-dev/hook-vault/internal/webui"
)

// Every template must parse at test time with the real func map: text/template
// resolves functions at parse, so a typo or a missing func only fails when a
// page is rendered in production otherwise.
func TestPanelTemplatesParse(t *testing.T) {
	pages, err := fs.Glob(webui.FS, "templates/*.html")
	if err != nil {
		t.Fatalf("glob templates: %v", err)
	}
	if len(pages) < 4 {
		t.Fatalf("expected at least 4 templates, found %d", len(pages))
	}
	for _, page := range pages {
		if page == "templates/layout.html" {
			continue
		}
		tmpl := template.New("layout.html").Funcs(templateFuncs)
		if _, err := tmpl.ParseFS(webui.FS, "templates/layout.html", page); err != nil {
			t.Errorf("parse %s: %v", page, err)
		}
	}
}
