package main

import (
	"testing"
)

func TestEnforcePasswordPolicy(t *testing.T) {
	cfg.PasswordPolicy.MinLength = 12
	cfg.PasswordPolicy.MaxLength = 24
	cfg.PasswordPolicy.LowerCase = true
	cfg.PasswordPolicy.UpperCase = true
	cfg.PasswordPolicy.Digits = true
	cfg.PasswordPolicy.SepcialChar = true

	passwords := make(map[string]bool)

	passwords["fWO5pnZ"] = false                     // too short
	passwords["poXANQPFPpg94lYBpvvpeKnsoth"] = false // too long
	passwords["caieg7vd0x08i9hfz#qqyq"] = false      // no upper case
	passwords["dTtdXllvOQNYBUsTA+VTKC"] = false      // no digit
	passwords["0oI0nDfKEE4hhh2YpZKsMn"] = false      // no symbol
	passwords[";c>$:p3p!>LFloN/x3!;yl"] = true

	for k, v := range passwords {
		got, message := enforcePasswordPolicy(k)
		want := v

		if got != want {
			t.Errorf("got %t want %t; Message: %s", got, want, message)
		}
	}
}
