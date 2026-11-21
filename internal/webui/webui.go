// Package webui holds the control-plane UI. Templates and static assets are
// embedded so a released binary serves the panel with no build step and no
// filesystem dependency.
//
// Everything the panel shows comes from the same control-plane API the CLI
// uses; the panel adds no endpoint of its own except its pages and the login.
package webui

import "embed"

// FS carries templates/ and static/.
//
//go:embed templates static
var FS embed.FS
