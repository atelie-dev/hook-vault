package timespec

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		in      string
		want    time.Time
		wantErr bool
	}{
		{in: "10m", want: now.Add(-10 * time.Minute)},
		{in: "1h30m", want: now.Add(-90 * time.Minute)},
		{in: "10min", want: now.Add(-10 * time.Minute)},
		{in: "10MINS", want: now.Add(-10 * time.Minute)},
		{in: "2days", want: now.Add(-48 * time.Hour)},
		{in: "1week", want: now.Add(-7 * 24 * time.Hour)},
		{in: "0", want: now},
		{in: "2026-11-21T08:00:00Z", want: time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)},
		{in: "2026-11-21T05:00:00-03:00", want: time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)},
		{in: "", wantErr: true},
		{in: "banana", wantErr: true},
		{in: "10 fortnights", wantErr: true},
		{in: "-5m", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := Parse(tc.in, now)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
