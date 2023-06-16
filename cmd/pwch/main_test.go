package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDeleteFromHashMap(t *testing.T) {
	m := oneTimeURLs.m
	key := "test_key"
	value := time.Now()

	// Add a value to the map
	m[key] = value

	// Call the function to delete the key from the map
	deleteFromHashMap(m, key)

	// Check that the key has been removed
	if _, ok := m[key]; ok {
		t.Errorf("Expected key '%s' to be deleted, but it still exists in the map", key)
	}
}

func TestAddToHashMap(t *testing.T) {
	m := oneTimeURLs.m
	key := "test_key"
	value := time.Now()

	// Call the function to add a key-value pair to the map
	addToHashMap(m, key, value)

	// Check that the key-value pair exists in the map
	if val, ok := m[key]; !ok || val != value {
		t.Errorf("Expected key-value pair '%s:%v' to be added to the map, but it is not present or the value is incorrect", key, value)
	}
}

func TestEnforcePasswordPolicy(t *testing.T) {

	cfg.PasswordPolicy.MinLength = 12
	cfg.PasswordPolicy.MaxLength = 24
	cfg.PasswordPolicy.LowerCase = true
	cfg.PasswordPolicy.UpperCase = true
	cfg.PasswordPolicy.Digits = true
	cfg.PasswordPolicy.SepcialChar = true

	testPassword := func(t testing.TB, password, expectedMessage string) {
		t.Helper()

		valid, message := enforcePasswordPolicy(password)

		if valid {
			t.Errorf("Expected invalid password for input '%s', but got valid", password)
		}

		if message != expectedMessage {
			t.Errorf("Expected error message '%s', but got: %s", expectedMessage, message)
		}

	}

	// Test case 1: Valid password that meets all requirements
	password := "StrongPassword123!"
	valid, message := enforcePasswordPolicy(password)
	if !valid {
		t.Errorf("Expected valid password for input '%s', but got invalid", password)
	}
	if message != "Success" {
		t.Errorf("Expected success message for valid password, but got: %s", message)
	}

	// Test case 2
	t.Run("password of insufficient length", func(t *testing.T) {
		password = "short"
		expectedMessage := fmt.Sprintf("Please enter at least a %d character long password", cfg.PasswordPolicy.MinLength)
		testPassword(t, password, expectedMessage)
	})

	// Test case 3
	t.Run("password exceeding maximum length", func(t *testing.T) {
		password = "thispasswordexceedsthemaximumallowedlength"
		expectedMessage := fmt.Sprintf("Please enter at max a %d character long password", cfg.PasswordPolicy.MaxLength)
		testPassword(t, password, expectedMessage)
	})

	// Test case 4
	t.Run("password missing lower case character", func(t *testing.T) {
		password = "PASSWORD123!"
		expectedMessage := "Please enter at least one lower case character"
		testPassword(t, password, expectedMessage)
	})

	// Test case 5
	t.Run("password missing upper case character", func(t *testing.T) {
		password = "password123!"
		expectedMessage := "Please enter at least one upper case character"
		testPassword(t, password, expectedMessage)
	})

	// Test case 6
	t.Run("password missing digit", func(t *testing.T) {
		password = "PasswordWithoutDigit!"
		expectedMessage := "Please enter at least one digit"
		testPassword(t, password, expectedMessage)
	})

	// Test case 7
	t.Run("password missing special character", func(t *testing.T) {
		password = "PasswordNoSpecial123"
		expectedMessage := "Please enter at least one special character"
		testPassword(t, password, expectedMessage)
	})
}

func TestValidatePasswordFields(t *testing.T) {
	newPass := "newPassword"
	confirmPass := "newPassword"
	oldPass := "oldPassword"

	// Test case 1: Valid input
	err := validatePasswordFields(newPass, confirmPass, oldPass)
	if err != nil {
		t.Errorf("Expected no error for valid input, but got: %s", err.Error())
	}

	// Test case 2: Mismatched passwords
	confirmPass = "wrongPassword"
	err = validatePasswordFields(newPass, confirmPass, oldPass)
	if err == nil {
		t.Error("Expected error for mismatched passwords, but got no error")
	} else if err.Error() != "Passwords do not match" {
		t.Errorf("Expected error message 'Passwords do not match', but got: %s", err.Error())
	}

	// Test case 3: Same old and new passwords
	newPass = "oldPassword"
	confirmPass = "oldPassword"
	err = validatePasswordFields(newPass, confirmPass, oldPass)
	if err == nil {
		t.Error("Expected error for setting same password again, but got no error")
	} else if err.Error() != "You are trying to set the same password again" {
		t.Errorf("Expected error message 'You are trying to set the same password again', but got: %s", err.Error())
	}
}

//
// handler section
//

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

func TestEmailSendHandler(t *testing.T) {
	cfg.DB.Host = "/run/postgresql"
	cfg.DB.DBName = "vmail"
	cfg.DB.User = "vmail"
	cfg.DB.Password = "password"
	cfg.DB.SSLMode = "disable"

	cfg.SMTP.Host = "localhost"
	cfg.SMTP.Port = "587"
	cfg.SMTP.LoginUser = "noreply@localdomain"
	cfg.SMTP.LoginPassword = "password"
	cfg.SMTP.Sender = "noreply@localdomain"

	form := url.Values{}
	form.Add("email", "pwch1@localdomain")
	req, err := http.NewRequest("POST", "/emailSend", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.PostForm = form

	// Create a response recorder to capture the response
	rr := httptest.NewRecorder()

	// Redirect log output to a buffer
	var buf bytes.Buffer
	log.SetOutput(&buf)

	// Call the handler function
	emailSendHandler(rr, req)

	// Check the response status code
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, rr.Code)
	}

	expected := "<title>Password Reset</title>"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("handler returned unexpected body: %v not found", expected)
	}

	// wait for email being sent
	time.Sleep(1000 * time.Millisecond)

	// Get the log output from the buffer
	output := buf.String()

	// Remove the date and timestamp portion from the log messages
	re := regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)
	cleanedOutput := re.ReplaceAllString(output, "")

	expected = "INFO: pwch1@localdomain successfully validated\n" +
		"INFO: Sent OTL to pwch1@localdomain\n"

	if cleanedOutput != expected {
		t.Errorf("Unexpected log output.\nExpected: %s\nActual: %s", expected, cleanedOutput)
	}
}

func TestPasswordChangeHandler(t *testing.T) {
	cfg.AssetsPath = "../../assets/html"

	getResetPage := func(t testing.TB, url, expected string) {
		t.Helper()

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()

		// Call the handler function
		passwordChangeHandler(rr, req)

		// Check the response status code
		if rr.Code != http.StatusOK {
			t.Errorf("expected status code %d, got %d", http.StatusOK, rr.Code)
		}

		// Check the response body
		expectedBody := expected
		if !strings.Contains(rr.Body.String(), expectedBody) {
			t.Errorf("handler returned unexpected body: %v not found", expectedBody)
		}
	}

	// Test case 1: valid URL
	t.Run("test with valid URL", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"
		addToHashMap(oneTimeURLs.m, url, time.Now())

		getResetPage(t, url, "<title>Password Reset</title>")
	})

	// Test case 2: invalid/expired URL
	t.Run("test with invalid URL", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"

		getResetPage(t, url, "Link expired")
	})
}
