package main

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestPasswordChangeHandler(t *testing.T) {
	testData := changePasswordTemplateData{
		Token:    "abcd",
		Username: "test",
		Domain:   "example.com",
		Length:   12,
		Lower:    true,
		Upper:    true,
		Digit:    true,
		Special:  true,
	}

	cfg.AssetsPath = "../../html"
	var url = "changePassword?token=abcd&username=test&domain=example.com"
	addToHashMap(oneTimeURLs.m, url, time.Now())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(passwordChangeHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	tmpl, err := template.ParseFiles(cfg.AssetsPath + "/changePassword.html")
	if err != nil {
		t.Fatal(err)
	}

	buffer := &bytes.Buffer{}
	err = tmpl.Execute(buffer, testData)
	if err != nil {
		t.Fatal(err)
	}

	if rr.Body.String() != buffer.String() {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), buffer.String())
	}
}
