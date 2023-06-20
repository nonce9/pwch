package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// custom error reader
type errorReader struct{}

func (r errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("custom error")
}

func TestPrintBuildInfo(t *testing.T) {
	// Create a pipe to capture standard output
	readPipe, writePipe, _ := os.Pipe()
	defer readPipe.Close()

	// Redirect standard output to the write end of the pipe
	oldStdout := os.Stdout
	os.Stdout = writePipe

	printBuildInfo()

	// Restore standard output
	os.Stdout = oldStdout
	writePipe.Close()

	// Read the captured output from the read end of the pipe
	var outputBytes []byte
	outputBytes, _ = io.ReadAll(readPipe)
	output := string(outputBytes)

	if !strings.Contains(output, "pwch version:") {
		t.Errorf("Unexpected help message.\nGot:\n%s", output)
	}
}

func TestPrintHelp(t *testing.T) {
	// Create a pipe to capture standard output
	readPipe, writePipe, _ := os.Pipe()
	defer readPipe.Close()

	// Redirect standard output to the write end of the pipe
	oldStdout := os.Stdout
	os.Stdout = writePipe

	printHelp()

	// Restore standard output
	os.Stdout = oldStdout
	writePipe.Close()

	// Read the captured output from the read end of the pipe
	var outputBytes []byte
	outputBytes, _ = io.ReadAll(readPipe)
	output := string(outputBytes)

	expectedHelp := `Possible arguments:
	--config		Changes default path from where to read the config file.
	--help			Print this help statement.
	--version		Print version and build info.`

	if strings.TrimSpace(output) != strings.TrimSpace(expectedHelp) {
		t.Errorf("Unexpected help message.\nExpected:\n%s\nGot:\n%s", expectedHelp, output)
	}
}

func TestReadFile(t *testing.T) {
	cfg := &config{}

	loadConfig := func(t testing.TB, path string) error {
		t.Helper()
		configPath = path
		return readFile(cfg)
	}

	// Test case 1
	t.Run("test non existing config file", func(t *testing.T) {
		err := loadConfig(t, "config.yml")

		if err.Error() != "open config.yml: no such file or directory" {
			t.Errorf("Unexpected error occurred: %v", err)
		}

	})

	// Test case 2
	t.Run("test unmarshal error", func(t *testing.T) {
		err := loadConfig(t, "../../config/pwch.service")

		if !strings.Contains(err.Error(), "yaml: unmarshal errors") {
			t.Errorf("Unexpected error occurred: %v", err)
		}
	})

	// Test case 3
	t.Run("test successful case", func(t *testing.T) {
		err := loadConfig(t, "../../config/config.yml")

		if err != nil {
			t.Errorf("Expected error to be nil, but got: %v", err)
		}

		expectedDomain := "example.com"
		if cfg.Domain != expectedDomain {
			t.Errorf("Expected Domain: %s, Got: %s", expectedDomain, cfg.Domain)
		}
	})
}

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

func TestGenRandomBytes(t *testing.T) {
	t.Run("unexpected length", func(t *testing.T) {
		length := 10
		randomBytes, err := genRandomBytes(length)

		if err != nil {
			t.Errorf("Error generating random bytes: %v", err)
		}
		if len(randomBytes) != length {
			t.Errorf("Unexpected length of random bytes.\nExpected: %d\nGot: %d", length, len(randomBytes))
		}

	})

	t.Run("unexpected error", func(t *testing.T) {
		// Replace the default rand.Reader with the errorReader
		originalReader := rand.Reader
		rand.Reader = errorReader{}

		randomBytes, err := genRandomBytes(10)

		// Restore the original rand.Reader
		rand.Reader = originalReader

		if err == nil {
			t.Error("Expected error, but got nil")
		} else {
			expectedError := "custom error"
			if err.Error() != expectedError {
				t.Errorf("Unexpected error.\nExpected: %s\nGot: %s", expectedError, err.Error())
			}
		}

		if randomBytes != nil {
			t.Errorf("Expected nil byte slice, but got: %v", randomBytes)
		}
	})
}

func TestIsValidEmail(t *testing.T) {
	// Test case 1
	email := "test@example.com"
	result := isValidEmail(email)
	if result == false {
		t.Errorf("Got %s is invail but should be vaild", email)
	}

	// Test case 2
	email = "testexample.com"
	result = isValidEmail(email)
	if result == true {
		t.Errorf("Got %s is vail but should be invaild", email)
	}
}

func TestSendOneTimeLink(t *testing.T) {
	testSMTP := func(t testing.TB, username, domain string) string {
		t.Helper()

		var buf bytes.Buffer
		log.SetOutput(&buf)

		sendOneTimeLink(username, domain)

		// Get the log output from the buffer
		output := buf.String()

		// Remove the date and timestamp portion from the log messages
		re := regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)
		cleanedOutput := re.ReplaceAllString(output, "")

		log.SetOutput(os.Stdout)
		return cleanedOutput
	}

	// Test case 1
	t.Run("test successful delivery", func(t *testing.T) {
		got := testSMTP(t, "pwch1", "localdomain")
		want := "dial tcp :0: connect: connection refused\n" +
			"ERROR: Sending OTL failed\n"

		if got != want {
			t.Errorf("\nGot:\n%s\nWant:\n%s", got, want)
		}
	})

	// Test case 2
	t.Run("test failed delivery", func(t *testing.T) {
		got := testSMTP(t, "test", "127.0.0.1")
		want := "dial tcp :0: connect: connection refused\n" +
			"ERROR: Sending OTL failed\n"

		if got != want {
			t.Errorf("\nGot:\n%s\nWant:\n%s", got, want)
		}
	})
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

func TestReencryptMailbox(t *testing.T) {
	testReencryption := func(t testing.TB, username, oldPassword, newPassword string) (error, string) {
		t.Helper()

		var buf bytes.Buffer
		log.SetOutput(&buf)

		err := reencryptMailbox(username, oldPassword, newPassword)

		// Get the log output from the buffer
		output := buf.String()

		// Remove the date and timestamp portion from the log messages
		re := regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)
		cleanedOutput := re.ReplaceAllString(output, "")

		log.SetOutput(os.Stdout)
		return err, cleanedOutput
	}

	// Test case 1
	t.Run("successful reencryption", func(t *testing.T) {
		err, logMessage := testReencryption(t, "pwch2@localdomain", "password", "StrongPassword1234!")

		if err != nil {
			t.Errorf("want nil but got %v", err)
		}

		if !strings.Contains(logMessage, "Successfully") {
			t.Errorf("got unexpected log message: %s", logMessage)
		}
	})

	// Test case 2
	t.Run("failed reencryption of same user again", func(t *testing.T) {
		err, logMessage := testReencryption(t, "pwch2@localdomain", "password", "StrongPassword1234!")

		if err == nil {
			t.Errorf("want error but got nil")
		}

		if !strings.Contains(logMessage, "exit status 65") {
			t.Errorf("got unexpected log message: %s", logMessage)
		}
	})

	// Test case 3
	t.Run("failed reencryption of another user", func(t *testing.T) {
		err, logMessage := testReencryption(t, "pwch3@localdomain", "password123", "StrongPassword1234!")

		if err == nil {
			t.Errorf("want error but got nil")
		}

		if !strings.Contains(logMessage, "exit status 65") {
			t.Errorf("got unexpected log message: %s", logMessage)
		}
	})

	// Test case 4
	t.Run("non existing user", func(t *testing.T) {
		err, logMessage := testReencryption(t, "test@localdomain", "password", "StrongPassword1234!")

		if err == nil {
			t.Errorf("want error but got nil")
		}

		if !strings.Contains(logMessage, "exit status 67") {
			t.Errorf("got unexpected log message: %s", logMessage)
		}
	})

	// Test case 5
	t.Run("revert test case 1", func(t *testing.T) {
		err, logMessage := testReencryption(t, "pwch2@localdomain", "StrongPassword1234!", "password")

		if err != nil {
			t.Errorf("want nil but got %v", err)
		}

		if !strings.Contains(logMessage, "Successfully") {
			t.Errorf("got unexpected log message: %s", logMessage)
		}
	})
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

	checkEmailAddress := func(t testing.TB, expectedBody, method string, expectedCode int, pause bool) string {
		t.Helper()

		// Redirect log output to a buffer
		var buf bytes.Buffer
		log.SetOutput(&buf)

		req, err := http.NewRequest(method, "/emailSend", nil)
		if err != nil {
			t.Fatal(err)
		}

		if method == "POST" {
			req.PostForm = form
		}

		rr := httptest.NewRecorder()

		emailSendHandler(rr, req)

		if pause {
			time.Sleep(500 * time.Millisecond)
		}
		output := buf.String()

		// Remove the date and timestamp portion from the log messages
		re := regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} `)
		cleanedOutput := re.ReplaceAllString(output, "")

		// Check the response status code
		if rr.Code != expectedCode {
			t.Errorf("Expected status code %d, but got %d", expectedCode, rr.Code)
		}

		// Check the response body
		if !strings.Contains(rr.Body.String(), expectedBody) {
			t.Errorf("handler returned unexpected body: %v not found", expectedBody)
		}

		// reset log output to stdout
		log.SetOutput(os.Stdout)

		return cleanedOutput
	}

	// Test case 1
	t.Run("test valid email address", func(t *testing.T) {
		form.Add("email", "pwch1@localdomain")

		logOutput := checkEmailAddress(t, "an email may have been sent", "POST", http.StatusOK, true)

		expected := "INFO: pwch1@localdomain successfully validated\n" +
			"INFO: Sent OTL to pwch1@localdomain\n"

		if logOutput != expected {
			t.Errorf("Unexpected log output.\nExpected: %s\nActual: %s", expected, logOutput)
		}
	})

	// Test case 2
	// reset rate limiting
	lastEmailSent = time.Now().Add(-10 * time.Minute)
	form = url.Values{}
	t.Run("test invalid email address", func(t *testing.T) {
		form.Add("email", "invalid@localdomain")

		logOutput := checkEmailAddress(t, "an email may have been sent", "POST", http.StatusOK, false)

		expected := "INFO: Unknown email address: invalid@localdomain\n"

		if logOutput != expected {
			t.Errorf("Unexpected log output.\nExpected: %s\nActual: %s", expected, logOutput)
		}
	})

	// Test case 3
	lastEmailSent = time.Now()
	form = url.Values{}
	t.Run("test rate limiting", func(t *testing.T) {
		form.Add("email", "pwch1@localdomain")

		_ = checkEmailAddress(t, "Too early", "POST", http.StatusTooEarly, false)
	})

	// Test case 4
	t.Run("test wrong method", func(t *testing.T) {
		_ = checkEmailAddress(t, "Method not allowed", "GET", http.StatusMethodNotAllowed, false)
	})

	form = url.Values{}
	// Test case 5
	t.Run("test wrong email syntax", func(t *testing.T) {
		form.Add("email", "pwch1localdomain")

		_ = checkEmailAddress(t, "Please enter a valid email address", "POST", http.StatusOK, false)
	})
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

	// Test case 1
	t.Run("test with valid URL", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"
		addToHashMap(oneTimeURLs.m, url, time.Now())

		getResetPage(t, url, "<title>Password Reset</title>")
	})

	// Test case 2
	t.Run("test with invalid URL", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"

		getResetPage(t, url, "Link expired")
	})
}

func TestPasswordSubmitHandler(t *testing.T) {
	// discard log output for this function
	log.SetOutput(ioutil.Discard)

	// set password policy
	cfg.PasswordPolicy.MinLength = 6
	cfg.PasswordPolicy.MaxLength = 24
	cfg.PasswordPolicy.LowerCase = true
	cfg.PasswordPolicy.UpperCase = true
	cfg.PasswordPolicy.Digits = false
	cfg.PasswordPolicy.SepcialChar = false

	cfg.AssetsPath = "../../assets/html"

	form := url.Values{}

	getResultPage := func(t testing.TB, url, expectedBody string, expectedCode int) {
		t.Helper()

		req, err := http.NewRequest("POST", "/submitPassword/"+url, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.PostForm = form

		rr := httptest.NewRecorder()

		// Call the handler function
		passwordSubmitHandler(rr, req)

		// Check the response status code
		if rr.Code != expectedCode {
			t.Errorf("expected status code %d, got %d", expectedCode, rr.Code)
		}

		// Check the response body
		if !strings.Contains(rr.Body.String(), expectedBody) {
			t.Errorf("handler returned unexpected body: %v not found", expectedBody)
		}
	}

	// Test case 1
	t.Run("test full workflow", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"
		addToHashMap(oneTimeURLs.m, url, time.Now())

		form.Add("current-password", "password")
		form.Add("new-password", "StrongPassword123!")
		form.Add("confirm-password", "StrongPassword123!")

		getResultPage(t, url, "Success", http.StatusOK)
	})

	// Test case 2
	t.Run("test workflow again with same credentials and fail", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"
		addToHashMap(oneTimeURLs.m, url, time.Now())

		form.Add("current-password", "password")
		form.Add("new-password", "StrongPassword123!")
		form.Add("confirm-password", "StrongPassword123!")

		getResultPage(t, url, "Current Password does not match", http.StatusOK)
	})

	// Test case 3
	form = url.Values{}
	t.Run("test redirect for expired link", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"

		form.Add("current-password", "StrongPassword1234!")
		form.Add("new-password", "StrongPassword123!+")
		form.Add("confirm-password", "StrongPassword123!+")

		getResultPage(t, url, "", http.StatusFound)
	})

	// Test case 4
	form = url.Values{}
	t.Run("test missmatching passwords", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"
		addToHashMap(oneTimeURLs.m, url, time.Now())

		form.Add("current-password", "password")
		form.Add("new-password", "StrongPassword1234!")
		form.Add("confirm-password", "StrongPassword123!")

		getResultPage(t, url, "Passwords do not match", http.StatusOK)
	})

	// Test case 5
	form = url.Values{}
	t.Run("test setting the same password", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"
		addToHashMap(oneTimeURLs.m, url, time.Now())

		form.Add("current-password", "password")
		form.Add("new-password", "password")
		form.Add("confirm-password", "password")

		getResultPage(t, url, "You are trying to set the same password again", http.StatusOK)
	})

	// Test case 6
	form = url.Values{}
	t.Run("test password policy violation", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"
		addToHashMap(oneTimeURLs.m, url, time.Now())

		form.Add("current-password", "password")
		form.Add("new-password", "password123")
		form.Add("confirm-password", "password123")

		getResultPage(t, url, "Please enter at least one upper case character", http.StatusOK)
	})

	// Test case 7
	form = url.Values{}
	t.Run("revert test case 1", func(t *testing.T) {
		token, _ := genRandomString(64)
		url := "changePassword?token=" + token + "&username=pwch1&domain=localdomain"
		addToHashMap(oneTimeURLs.m, url, time.Now())

		form.Add("current-password", "StrongPassword123!")
		form.Add("new-password", "password")
		form.Add("confirm-password", "password")

		cfg.PasswordPolicy.UpperCase = false

		getResultPage(t, url, "Success", http.StatusOK)
	})

	// restore log output to stdout
	log.SetOutput(os.Stdout)
}
