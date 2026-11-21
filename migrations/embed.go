// Package migrations embeds the SQL schema so a released binary can migrate
// its own database.
package migrations

import "embed"

// FS holds every migration, applied in lexical order.
//
//go:embed *.sql
var FS embed.FS
