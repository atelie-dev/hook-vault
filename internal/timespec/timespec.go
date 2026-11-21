// Package timespec parses the "since" forms hook-vault accepts, in one place so
// the CLI and the read API cannot drift apart:
//
//	10m          Go duration
//	1h30m        Go duration, compound
//	10min        kubectl-like word form (also 2days, 3hours, 1week)
//	2026-11-21T08:00:00Z   absolute, RFC3339
//
// A duration is resolved against the caller's clock. The read API resolves it
// against the database server's clock, so "the last 10 minutes" means the same
// thing to the events' received_at.
package timespec

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var wordForm = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([a-z]+)$`)

var units = map[string]time.Duration{
	"s": time.Second, "sec": time.Second, "secs": time.Second,
	"second": time.Second, "seconds": time.Second,
	"m": time.Minute, "min": time.Minute, "mins": time.Minute,
	"minute": time.Minute, "minutes": time.Minute,
	"h": time.Hour, "hr": time.Hour, "hrs": time.Hour,
	"hour": time.Hour, "hours": time.Hour,
	"d": 24 * time.Hour, "day": 24 * time.Hour, "days": 24 * time.Hour,
	"w": 7 * 24 * time.Hour, "week": 7 * 24 * time.Hour, "weeks": 7 * 24 * time.Hour,
}

// Parse resolves value against now.
//
// An empty value is an error: callers decide what "no filter" means, and it is
// easier to keep that decision in one place per caller.
func Parse(value string, now time.Time) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time specification")
	}

	if absolute, err := time.Parse(time.RFC3339, value); err == nil {
		return absolute, nil
	}
	if absolute, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return absolute, nil
	}

	if duration, err := time.ParseDuration(value); err == nil {
		if duration < 0 {
			return time.Time{}, fmt.Errorf("%q is negative: %q means 'the last %s'", value, value, -duration)
		}
		return now.Add(-duration), nil
	}

	if match := wordForm.FindStringSubmatch(strings.ToLower(value)); match != nil {
		amount, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid amount in %q", value)
		}
		unit, ok := units[match[2]]
		if !ok {
			return time.Time{}, fmt.Errorf("unknown unit %q in %q (try s, min, h, day, week)", match[2], value)
		}
		return now.Add(-time.Duration(amount * float64(unit))), nil
	}

	return time.Time{}, fmt.Errorf("%q is not a duration (10m, 10min, 2h) or an RFC3339 timestamp", value)
}
