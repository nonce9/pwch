package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"net/mail"
	"net/smtp"
	"os"
	"os/exec"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v2"
)

const version = "0.3.1"
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const lowercase = "abcdefghijklmnopqrstuvwxyz"
const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const digits = "0123456789"

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

var oneTimeURLs = struct {
	sync.RWMutex
	m map[string]time.Time
}{m: make(map[string]time.Time)}

type mailUser struct {
	Enabled  bool
	Username string
	Domain   string
}

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

func printVersion() {
	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		panic("Can't read BuildInfo")
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

func genRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
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
	tmpl.Execute(w, errorMessage)
}

func enforcePasswordPolicy(password string) (bool, string) {

	// initialize with opposite of config value
	// policies set to "false" will therefore init with "true" and will not change
	hasLower := !cfg.PasswordPolicy.LowerCase
	hasUpper := !cfg.PasswordPolicy.UpperCase
	hasNumber := !cfg.PasswordPolicy.Digits
	hasSpecial := !cfg.PasswordPolicy.SepcialChar
	errorMessage := "Undefined error"

	if len(password) < cfg.PasswordPolicy.MinLength {
		return false, "Please enter at least a " +
			strconv.Itoa(cfg.PasswordPolicy.MinLength) + " character long password"
	}

	if len(password) > cfg.PasswordPolicy.MaxLength {
		return false, "Please enter at max a " +
			strconv.Itoa(cfg.PasswordPolicy.MaxLength) + " character long password"
	}

	for _, char := range password {
		switch {
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsPunct(char):
			hasSpecial = true
		case unicode.IsSpace(char):
			hasSpecial = true
		case unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if hasLower && hasUpper && hasNumber && hasSpecial {
		return true, "Success"
	}

	if !hasLower {
		errorMessage = "Please enter at least one lower case character"
	}

	if !hasUpper {
		errorMessage = "Please enter at least one upper case character"
	}

	if !hasNumber {
		errorMessage = "Please enter at least one digit"
	}

	if !hasSpecial {
		errorMessage = "Please enter at least one special character"
	}

	return false, errorMessage
}

func sendOneTimeLink(username, domain string) {
	var token = genRandomString(64)

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

	err := smtp.SendMail(host+":"+port, auth, loginUser, to, message)
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

func emailEnabled(email string) (bool, mailUser) {
	components := strings.Split(email, "@")
	username, domain := components[0], components[1]

	var db = connectToDatabase()

	stmt, err := db.Prepare("SELECT username, domain, enabled FROM accounts WHERE username = $1 AND domain = $2;")
	if err != nil {
		db.Close()
		log.Fatal(err)
	}

	var mailUser mailUser

	err = stmt.QueryRow(username, domain).Scan(&mailUser.Username, &mailUser.Domain, &mailUser.Enabled)
	if err != nil {
		if err == sql.ErrNoRows {
			db.Close()
			log.Print("INFO: Unknown email address: " + username + "@" + domain)
			return false, mailUser
		}
		log.Fatal(err)
	}

	db.Close()

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
			db.Close()
			return false
		}
	}
	db.Close()

	if checkPasswordHash(oldPass, hash) {
		log.Print("INFO: Successfully validated old password for " + username + "@" + domain)
		return true
	}
	log.Print("ERROR: Can't validate old password for " + username + "@" + domain)
	return false
}

func reencryptMailbox(email string, oldPass string, newPass string) bool {
	oldHash := sha3.New512()
	newHash := sha3.New512()

	oldHash.Write([]byte(oldPass))
	newHash.Write([]byte(newPass))

	oldHashString := hex.EncodeToString(oldHash.Sum(nil))
	newHashString := hex.EncodeToString(newHash.Sum(nil))

	cmd := exec.Command("/usr/local/bin/doveadm_wrapper", "swap", email, oldHashString, newHashString)
	err := cmd.Run()

	if err == nil {
		log.Print("INFO: Successfully swapped keys for " + email)
		return true
	}
	log.Print("ERROR: Can't swap keys for " + email)
	log.Print(err)
	return false
}

func terminateIMAPSessions(email string) bool {
	cmd := exec.Command("/usr/local/bin/doveadm_wrapper", "kick", email)
	err := cmd.Run()

	if err == nil {
		log.Print("INFO: Successfully terminated all sessions for " + email)
		return true
	}

	if exitError, ok := err.(*exec.ExitError); ok {
		if exitError.ExitCode() == 68 {
			log.Print("INFO: No active sessions to terminate for " + email)
			return true
		}
	}

	log.Print("ERROR: Can't terminate sessions for " + email)
	log.Print(err)
	return false
}

//
// handler section
//

func submitEmailHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, cfg.AssetsPath+"/submitEmail.html")
}

func emailSendHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// rate limiting
	if time.Now().Sub(lastEmailSent) < (5 * time.Second) {
		w.WriteHeader(http.StatusTooEarly)
		fmt.Fprintf(w, "Too early. Please try again.")
		return
	}

	if !isValidEmail(email) {
		templatePasswordErrorPage(w, "Please enter a valid email address")
		return
	}

	http.Redirect(w, r, cfg.URLPrefix+"/emailSent", http.StatusSeeOther)

	enabled, mailUser := emailEnabled(email)

	if enabled {
		lastEmailSent = time.Now()
		go sendOneTimeLink(mailUser.Username, mailUser.Domain)
	}
}

func passwordChangeHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	username := r.URL.Query().Get("username")
	domain := r.URL.Query().Get("domain")

	var url = "changePassword?token=" + token +
		"&username=" + username +
		"&domain=" + domain

	_, ok := oneTimeURLs.m[url]
	if !ok {
		fmt.Fprintf(w, "Link expired")
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
	}
	tmpl.Execute(w, data)
}

func passwordSubmitHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	username := r.URL.Query().Get("username")
	domain := r.URL.Query().Get("domain")

	email := username + "@" + domain

	oldPass := r.FormValue("current-password")
	newPass := r.FormValue("new-password")
	confirmPass := r.FormValue("confirm-password")

	var url = "changePassword?token=" + token +
		"&username=" + username +
		"&domain=" + domain

	_, ok := oneTimeURLs.m[url]
	if !ok {
		http.Redirect(w, r, "/", 302)
		return
	}

	enforced, enforcementError := enforcePasswordPolicy(newPass)

	if !((newPass == confirmPass) && (oldPass != newPass) && enforced) {
		switch {

		case newPass != confirmPass:
			templatePasswordErrorPage(w, "Passwords do not match")
			return

		case oldPass == newPass:
			templatePasswordErrorPage(w, "You are trying to set the same password again")
			return

		case !enforced:
			templatePasswordErrorPage(w, enforcementError)
			return

		default:
			break
		}
	}

	if !passwordMatches(username, domain, oldPass, newPass) {
		templatePasswordErrorPage(w, "Current password does not match")
		return
	}

	hash, err := hashPassword(newPass)

	if err != nil {
		log.Print(err)
		return
	}

	var db = connectToDatabase()

	ctx := context.Background()

	// Get a Tx for making transaction requests.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Print("ERROR: can't begin transaction")
	}

	// Defer a rollback in case anything fails.
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, "UPDATE accounts SET password = $1 WHERE username = $2 AND domain = $3;",
		string(hash), username, domain)
	if err != nil {
		log.Print("ERROR: password update query failed")
		db.Close()
		return
	}

	if reencryptMailbox(email, oldPass, newPass) {
		err = tx.Commit()
		if err != nil {
			log.Fatal(err)
		}
		db.Close()
		log.Print("INFO: Password successfully changed for " + email)

		terminateIMAPSessions(email)
	} else {
		db.Close()
		templatePasswordErrorPage(w, "Internal error: Password not changed")
		return
	}

	deleteFromHashMap(oneTimeURLs.m, url)
	log.Print("INFO: Deleted " + url + " from map")
	http.ServeFile(w, r, cfg.AssetsPath+"/success.html")
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
				printVersion()
				os.Exit(0)
			}
		}
		if os.Args[1] == "--config" {
			configPath = os.Args[2]
		}
	}

	readFile(&cfg)

	rand.Seed(time.Now().UnixNano())
	lastEmailSent = time.Now()

	mux := http.NewServeMux()

	mux.HandleFunc(cfg.URLPrefix+"/submitEmail", submitEmailHandler)
	mux.HandleFunc(cfg.URLPrefix+"/emailSend", emailSendHandler)
	mux.HandleFunc(cfg.URLPrefix+"/changePassword", passwordChangeHandler)
	mux.HandleFunc(cfg.URLPrefix+"/submitPassword", passwordSubmitHandler)

	log.Printf("pwch %s", version)
	log.Print("INFO: Listening on " + cfg.Server.ListenAddress + ":" + cfg.Server.Port)
	go func() {
		log.Fatal(http.ListenAndServe(cfg.Server.ListenAddress+":"+cfg.Server.Port, mux))
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
