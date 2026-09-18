package bwlimit

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"unlimited", 0, false},
		{"UNLIMITED", 0, false},
		{"", 0, false},
		{"500", 500, false},
		{"10K", 10 * 1024, false},
		{"10k", 10 * 1024, false},
		{"10M", 10 * 1024 * 1024, false},
		{"10G", 10 * 1024 * 1024 * 1024, false},
		{"10X", 0, true},
		{"-5", 0, true},
		{"0", 0, true},
		{"K", 0, true},
		{"1.5M", 0, true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %d, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
