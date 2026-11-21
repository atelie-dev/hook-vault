// Package webui exposes the pieces the control plane needs from the embedded
// UI.
package webui

import (
	"io/fs"
)

// Static returns the embedded static assets (CSS, keygen.js). The directory is
// embedded at compile time, so the error path is unreachable — a panic here
// means the build is broken, which is better than serving an empty panel.
func Static() fs.FS {
	sub, err := fs.Sub(FS, "static")
	if err != nil {
		panic("webui: static assets missing from the embedded FS: " + err.Error())
	}
	return sub
}
