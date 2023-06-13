package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAddToHashMap(t *testing.T) {
	addToHashMap(oneTimeURLs.m, "test", time.Now())

	var ti interface{} = time.Now()

	i := 0
	for _, v := range oneTimeURLs.m {
		i++
		if reflect.TypeOf(v) != reflect.TypeOf(ti) {
			t.Error("value has a wrong type")
		}
	}

	if i != 1 {
		t.Error("unexpected size of hash map")
	}
}

func TestDeleteFromHashMap(t *testing.T) {
	deleteFromHashMap(oneTimeURLs.m, "test")

	i := 0
	for range oneTimeURLs.m {
		i++
	}

	if i != 0 {
		t.Error("unexpected size of hash map")
	}
}

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
	passwords["POXANQPFPPG94LYBPVVPEK"] = false      // no lower case
	passwords["caieg7vd0x08i9hfz#qqyq"] = false      // no upper case
	passwords["dTtdXllvOQNYBUsTA+VTKC"] = false      // no digit
	passwords["0oI0nDfKEE4hhh2YpZKsMn"] = false      // no symbol
	passwords[";c>$:p3p!>LF oN/x3!;yl"] = true

	for k, v := range passwords {
		got, message := enforcePasswordPolicy(k)
		want := v

		if got != want {
			t.Errorf("got %t want %t; Message: %s", got, want, message)
		}
	}
}

func TestSubmitEmailHandler(t *testing.T) {
	cfg.AssetsPath = "../../assets/html"

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(submitEmailHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v, want %v", status, http.StatusOK)
	}

	expected := "<title>Password Reset</title>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: %v not found", expected)
	}
}
