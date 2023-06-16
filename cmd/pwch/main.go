// Copyright (C) 2023  Benedikt Zumtobel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unicode"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v3"
)

var version string
var configPath = "/etc/pwch/config.yml"
var cfg config
var lastEmailSent time.Time

type config struct {
	Domain     string `yaml:"domain"`
	URLPrefix  string `yaml:"url_prefix"`
	AssetsPath string `yaml:"assets_path"`
	Server     struct {
		ListenAddress string `yaml:"listen_address"`
		Port          string `yaml:"port"`
	} `yaml:"server"`
	DB struct {
		Host     string `yaml:"host"`
		DBName   string `yaml:"db_name"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		SSLMode  string `yaml:"ssl_mode"`
	} `yaml:"db"`
	Bcrypt struct {
		Cost int `yaml:"cost"`
	} `yaml:"bcrypt"`
	SMTP struct {
		Host          string `yaml:"host"`
		Port          string `yaml:"port"`
		LoginUser     string `yaml:"login_user"`
		LoginPassword string `yaml:"login_password"`
		Sender        string `yaml:"sender"`
	} `yaml:"smtp"`
	PasswordPolicy struct {
		MinLength   int  `yaml:"min_length"`
		MaxLength   int  `yaml:"max_length"`
		LowerCase   bool `yaml:"lower_case"`
		UpperCase   bool `yaml:"upper_case"`
		Digits      bool `yaml:"digits"`
		SepcialChar bool `yaml:"special_char"`
	} `yaml:"password_policy"`
	OTL struct {
		ValidFor time.Duration `yaml:"valid_for"`
	} `yaml:"otl"`
}

// this is where valid one time URLs are stored
//
// key   = random token + username + domain
// value = time at creation of entry
//
// entries are deleted either after the password
// got changed or when the entry expires
var oneTimeURLs = struct {
	sync.RWMutex
	m map[string]time.Time
}{m: make(map[string]time.Time)}

// used to fetch account attributes from database
type mailUser struct {
	Enabled  bool
	Username string
	Domain   string
}

// data object for html template
type changePasswordTemplateData struct {
	Token    string
	Username string
	Domain   string
	Length   int
	Lower    bool
	Upper    bool
	Digit    bool
	Special  bool
}

func printBuildInfo() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		log.Fatal("Can't read BuildInfo")
	}

	fmt.Println("pwch version:")
	fmt.Printf("  %s\n", version)

	fmt.Println("Built with:")
	fmt.Printf("  %s\n", buildInfo.GoVersion)

	fmt.Println("Dependencies:")
	if len(buildInfo.Deps) > 0 {
		for _, dep := range buildInfo.Deps {
			fmt.Printf("  %s \t %s\n", dep.Path, dep.Version)
		}
	} else {
		fmt.Println("  no external dependencies")
	}
}

func printHelp() {
	fmt.Println(`Possible arguments:
	--config		Changes default path from where to read the config file.
	--help			Print this help statement.
	--version		Print version and build info.`)
}

// reads config file
func readFile(cfg *config) {
	file, err := os.Open(configPath)
	if err != nil {
		log.Fatal(err)
	}

	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(cfg)
	if err != nil {
		log.Fatal(err)
	}
}

func deleteFromHashMap(m map[string]time.Time, key string) {
	oneTimeURLs.RLock()
	delete(oneTimeURLs.m, key)
	oneTimeURLs.RUnlock()
}

func addToHashMap(m map[string]time.Time, key string, value time.Time) {
	oneTimeURLs.Lock()
	oneTimeURLs.m[key] = value
	oneTimeURLs.Unlock()
}

func genRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func genRandomString(n int) (string, error) {
	b, err := genRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func templatePasswordErrorPage(w http.ResponseWriter, errorMessage string) {
	tmpl, err := template.ParseFiles(cfg.AssetsPath + "/error.html")
	if err != nil {
		log.Print(err)
	}
	err = tmpl.Execute(w, errorMessage)
	if err != nil {
		log.Print(err)
		log.Print("ERROR: cannot template error page")
	}
}

func sendOneTimeLink(username, domain string) {
	token, err := genRandomString(64)
	if err != nil {
		log.Print(err)
		log.Print("ERROR: cannot generate random string")
		return
	}

	loginUser := cfg.SMTP.LoginUser
	loginPassword := cfg.SMTP.LoginPassword
	from := cfg.SMTP.Sender
	to := []string{username + "@" + domain}
	host := cfg.SMTP.Host
	port := cfg.SMTP.Port

	accessString := "changePassword?token=" + token +
		"&username=" + username + "&domain=" + domain

	message := []byte("From: " + from + "\r\n" +
		"To: " + username + "@" + domain + "\r\n" +
		"Subject: Password change requested\r\n" +
		"\r\n" +
		"Follow this link to change your password:\r\n" +
		"\r\n" +
		"https://" + cfg.Domain + cfg.URLPrefix + "/" + accessString + "\r\n" +
		"\r\n" +
		"It's valid for 10 minutes.\r\n" +
		"\r\n" +
		"If you did not request a password change then just disregard this message.\r\n")

	auth := smtp.PlainAuth("", loginUser, loginPassword, host)

	err = smtp.SendMail(host+":"+port, auth, loginUser, to, message)
	if err != nil {
		log.Print(err)
		log.Print("ERROR: Sending OTL failed")
		return
	}

	addToHashMap(oneTimeURLs.m, accessString, time.Now())
	log.Print("INFO: Sent OTL to " + username + "@" + domain)
}

func connectToDatabase() *sql.DB {
	var db *sql.DB
	connStr := "user=" + cfg.DB.User + " password=" + cfg.DB.Password +
		" dbname=" + cfg.DB.DBName + " host=" + cfg.DB.Host +
		" sslmode=" + cfg.DB.SSLMode
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

func closeDatabase(db *sql.DB) error {
	return db.Close()
}

func emailEnabled(email string) (bool, mailUser) {
	components := strings.Split(email, "@")
	username, domain := components[0], components[1]

	var db = connectToDatabase()

	stmt, err := db.Prepare("SELECT username, domain, enabled FROM accounts WHERE username = $1 AND domain = $2;")
	if err != nil {
		_ = closeDatabase(db)
		log.Fatal(err)
	}

	var mailUser mailUser

	err = stmt.QueryRow(username, domain).Scan(&mailUser.Username, &mailUser.Domain, &mailUser.Enabled)
	if err != nil {
		if err == sql.ErrNoRows {
			_ = closeDatabase(db)
			log.Print("INFO: Unknown email address: " + username + "@" + domain)
			return false, mailUser
		}
		log.Fatal(err)
	}

	_ = closeDatabase(db)

	if mailUser.Enabled {
		log.Print("INFO: " + username + "@" + domain + " successfully validated")
		return true, mailUser
	}
	return false, mailUser
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cfg.Bcrypt.Cost)
	return string(bytes), err
}

func checkPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		log.Print(err)
		return false
	}
	return true
}

func passwordMatches(username string, domain string, oldPass string, newPass string) bool {
	var db = connectToDatabase()

	var hash string
	if err := db.QueryRow("SELECT password FROM accounts WHERE username = $1 AND domain = $2;",
		username, domain).Scan(&hash); err != nil {
		if err == sql.ErrNoRows {
			_ = closeDatabase(db)
			return false
		}
	}
	_ = closeDatabase(db)

	if checkPasswordHash(oldPass, hash) {
		log.Print("INFO: Successfully validated old password for " + username + "@" + domain)
		return true
	}
	log.Print("ERROR: Can't validate old password for " + username + "@" + domain)
	return false
}

func reencryptMailbox(email, oldPass, newPass string) error {
	oldHash := sha3.Sum512([]byte(oldPass))
	newHash := sha3.Sum512([]byte(newPass))

	oldHashString := hex.EncodeToString(oldHash[:])
	newHashString := hex.EncodeToString(newHash[:])

	cmd := exec.Command("/usr/local/bin/doveadm_wrapper", "swap")

	var input bytes.Buffer
	input.WriteString(email + "\n" + oldHashString + "\n" + newHashString + "\n")

	cmd.Stdin = &input

	err := cmd.Run()
	if err == nil {
		log.Printf("INFO: Successfully swapped keys for %s", email)
		return nil
	}

	log.Printf("ERROR: Can't swap keys for %s", email)
	log.Print(err)
	return err
}

func terminateIMAPSessions(email string) error {
	cmd := exec.Command("/usr/local/bin/doveadm_wrapper", "kick", email)
	err := cmd.Run()

	if err == nil {
		log.Printf("INFO: Successfully terminated all sessions for %s", email)
		return nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 68 {
		log.Printf("INFO: No active sessions to terminate for %s", email)
		return nil
	}

	log.Printf("ERROR: Can't terminate sessions for %s", email)
	log.Print(err)
	return err
}

//
// handler section
//

func submitEmailHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, cfg.AssetsPath+"/submitEmail.html")
}

func emailSendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	if !isValidEmail(email) {
		templatePasswordErrorPage(w, "Please enter a valid email address")
		return
	}

	// rate limiting
	if time.Since(lastEmailSent) < 5*time.Second {
		http.Error(w, "Too early. Please try again.", http.StatusTooEarly)
		return
	}

	http.ServeFile(w, r, cfg.AssetsPath+"/emailSent.html")

	if enabled, mailUser := emailEnabled(email); enabled {
		lastEmailSent = time.Now()
		go sendOneTimeLink(mailUser.Username, mailUser.Domain)
	}
}

func passwordChangeHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	username := r.URL.Query().Get("username")
	domain := r.URL.Query().Get("domain")

	url := fmt.Sprintf("changePassword?token=%s&username=%s&domain=%s", token, username, domain)

	if _, ok := oneTimeURLs.m[url]; !ok {
		fmt.Fprint(w, "Link expired")
		return
	}

	data := changePasswordTemplateData{
		Token:    token,
		Username: username,
		Domain:   domain,
		Length:   cfg.PasswordPolicy.MinLength,
		Lower:    cfg.PasswordPolicy.LowerCase,
		Upper:    cfg.PasswordPolicy.UpperCase,
		Digit:    cfg.PasswordPolicy.Digits,
		Special:  cfg.PasswordPolicy.SepcialChar,
	}

	tmpl, err := template.ParseFiles(cfg.AssetsPath + "/changePassword.html")
	if err != nil {
		log.Print(err)
		return
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Print(err)
		log.Print("ERROR: cannot execute template")
	}
}

func passwordSubmitHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	username := r.URL.Query().Get("username")
	domain := r.URL.Query().Get("domain")

	oldPass := r.FormValue("current-password")
	newPass := r.FormValue("new-password")
	confirmPass := r.FormValue("confirm-password")

	url := fmt.Sprintf("changePassword?token=%s&username=%s&domain=%s", token, username, domain)

	if _, ok := oneTimeURLs.m[url]; !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if err := validatePasswordFields(newPass, confirmPass, oldPass); err != nil {
		templatePasswordErrorPage(w, err.Error())
		return
	}

	if enforced, errMessage := enforcePasswordPolicy(newPass); enforced == false {
		templatePasswordErrorPage(w, errMessage)
		return
	}

	if err := updatePassword(username, domain, newPass, oldPass); err != nil {
		templatePasswordErrorPage(w, err.Error())
		return
	}

	deleteFromHashMap(oneTimeURLs.m, url)
	log.Print("INFO: Deleted " + url + " from map")
	http.ServeFile(w, r, cfg.AssetsPath+"/success.html")
}

func validatePasswordFields(newPass, confirmPass, oldPass string) error {
	if newPass != confirmPass {
		return errors.New("Passwords do not match")
	}

	if oldPass == newPass {
		return errors.New("You are trying to set the same password again")
	}

	return nil
}

func enforcePasswordPolicy(password string) (bool, string) {
	if len(password) < cfg.PasswordPolicy.MinLength {
		return false, fmt.Sprintf("Please enter at least a %d character long password", cfg.PasswordPolicy.MinLength)
	}

	if len(password) > cfg.PasswordPolicy.MaxLength {
		return false, fmt.Sprintf("Please enter at max a %d character long password", cfg.PasswordPolicy.MaxLength)
	}

	// initialize with opposite of config value
	// policies set to "false" will therefore init with "true" and will not change
	hasLower := !cfg.PasswordPolicy.LowerCase
	hasUpper := !cfg.PasswordPolicy.UpperCase
	hasNumber := !cfg.PasswordPolicy.Digits
	hasSpecial := !cfg.PasswordPolicy.SepcialChar

	for _, char := range password {
		switch {
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsPunct(char), unicode.IsSpace(char), unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if hasLower && hasUpper && hasNumber && hasSpecial {
		return true, "Success"
	}

	errorMessage := "Undefined error"
	if !hasLower {
		errorMessage = "Please enter at least one lower case character"
	} else if !hasUpper {
		errorMessage = "Please enter at least one upper case character"
	} else if !hasNumber {
		errorMessage = "Please enter at least one digit"
	} else if !hasSpecial {
		errorMessage = "Please enter at least one special character"
	}

	return false, errorMessage
}

// updates password in database, reencrypts mailbox and terminates IMAP sessions
func updatePassword(username, domain, newPass, oldPass string) error {
	hash, err := hashPassword(newPass)
	if err != nil {
		log.Print(err)
		return err
	}

	db := connectToDatabase()
	defer closeDatabase(db)

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Print("ERROR: can't begin transaction")
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "UPDATE accounts SET password = $1 WHERE username = $2 AND domain = $3;",
		string(hash), username, domain)
	if err != nil {
		log.Print("ERROR: password update query failed")
		return err
	}

	email := username + "@" + domain
	if err = reencryptMailbox(email, oldPass, newPass); err != nil {
		return errors.New("Internal error: Password not changed")
	}

	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
		return err
	}

	log.Print("INFO: Password successfully changed for " + email)
	err = terminateIMAPSessions(email)

	return err
}

func main() {
	// print pwch version and build info
	if len(os.Args) > 1 {
		for _, arg := range os.Args {
			if arg == "--help" {
				printHelp()
				os.Exit(0)
			}
		}
		for _, arg := range os.Args {
			if arg == "--version" {
				printBuildInfo()
				os.Exit(0)
			}
		}
		if os.Args[1] == "--config" {
			configPath = os.Args[2]
		}
	}

	readFile(&cfg)

	lastEmailSent = time.Now()

	mux := http.NewServeMux()

	mux.HandleFunc(cfg.URLPrefix+"/submitEmail", submitEmailHandler)
	mux.HandleFunc(cfg.URLPrefix+"/emailSend", emailSendHandler)
	mux.HandleFunc(cfg.URLPrefix+"/changePassword", passwordChangeHandler)
	mux.HandleFunc(cfg.URLPrefix+"/submitPassword", passwordSubmitHandler)

	srv := &http.Server{
		Addr:         cfg.Server.ListenAddress + ":" + cfg.Server.Port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("pwch %s", version)
	log.Print("INFO: Listening on " + cfg.Server.ListenAddress + ":" + cfg.Server.Port)
	go func() {
		log.Fatal(srv.ListenAndServe())
	}()

	ticker := time.NewTicker(30 * time.Second)
	for {
		<-ticker.C
		for k, v := range oneTimeURLs.m {
			if time.Now().Sub(v) > cfg.OTL.ValidFor {
				deleteFromHashMap(oneTimeURLs.m, k)
				log.Print("INFO: Deleted expired route " + k + " from map")
			}
		}
	}
}
