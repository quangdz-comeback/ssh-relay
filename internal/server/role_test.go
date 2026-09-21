package server

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		user       string
		role       Role
		deviceUser string
		alias      string
		wantErr    bool
	}{
		{"ssh", RoleDevice, "", "", false},
		{"ssh+json", RoleDeviceJSON, "", "", false},
		{"json", RoleStatus, "", "", false},
		{"d-7k2m9xq4tz", RoleClient, "root", "d-7k2m9xq4tz", false},
		{"root+d-7k2m9xq4tz", RoleClient, "root", "d-7k2m9xq4tz", false},
		{"deploy+MyVps", RoleClient, "deploy", "myvps", false},
		{"myvps", RoleClient, "root", "myvps", false},
		{"u0_a96", RoleClient, "root", "u0_a96", false},      // inner underscore (Termux)
		{"user+u0_a96", RoleClient, "user", "u0_a96", false}, // custom user + underscore
		{"_abc", RoleClient, "", "", true},                   // leading underscore
		{"ab_", RoleClient, "", "", true},                    // trailing underscore
		{"www.example.com", RoleClient, "", "", true},        // dot not allowed in alias
		{"ro ot+d-7k2m9xq4tz", RoleClient, "", "", true},     // space in user
		{"+d-7k2m9xq4tz", RoleClient, "", "", true},          // empty user
		{"root+", RoleClient, "", "", true},                  // empty alias
		{"root+ab", RoleClient, "", "", true},                // alias too short
		{"root+json", RoleClient, "", "", true},              // reserved alias
		{"help", RoleClient, "", "", true},                   // reserved username
		{"a b", RoleClient, "", "", true},
	}
	for _, c := range cases {
		got, err := Classify(c.user)
		if c.wantErr {
			if err == nil {
				t.Errorf("Classify(%q) = %+v, want error", c.user, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Classify(%q) unexpected error: %v", c.user, err)
			continue
		}
		if got.Role != c.role || got.DeviceUser != c.deviceUser || got.Alias != c.alias {
			t.Errorf("Classify(%q) = %+v, want role=%v user=%q alias=%q",
				c.user, got, c.role, c.deviceUser, c.alias)
		}
	}
}
