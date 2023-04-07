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

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v2"
)

const version = "0.1.1"
const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const lowercase = "abcdefghijklmnopqrstuvwxyz"
const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
const digits = "0123456789"

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
		MinLength int `yaml:"min_length"`
		MaxLength int `yaml:"max_length"`
	} `yaml:"password_policy"`
}

var oneTimeURLs = struct {
	sync.RWMutex
	m map[string]time.Time
}{m: make(map[string]time.Time)}

type url struct {
	Token    string
	Username string
	Domain   string
}

// reads config file
func readFile(cfg *config) {
	file, err := os.Open("/etc/pwch/config.yml")
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
	switch {

	case len(password) < cfg.PasswordPolicy.MinLength:
		return false, "Please enter at least a " +
			strconv.Itoa(cfg.PasswordPolicy.MinLength) + " character long password"

	case len(password) > cfg.PasswordPolicy.MaxLength:
		return false, "Please enter at max a " +
			strconv.Itoa(cfg.PasswordPolicy.MaxLength) + " character long password"

	case !strings.ContainsAny(password, lowercase):
		return false, "Please enter at least one lower case character"

	case !strings.ContainsAny(password, uppercase):
		return false, "Please enter at least one upper case character"

	case !strings.ContainsAny(password, digits):
		return false, "Please enter at least one digit"

	default:
		return true, "Success"
	}
}

func sendOneTimeLink(email string) {
	var token = genRandomString(64)

	loginUser := cfg.SMTP.LoginUser
	loginPassword := cfg.SMTP.LoginPassword
	from := cfg.SMTP.Sender
	to := []string{email}
	host := cfg.SMTP.Host
	port := cfg.SMTP.Port

	components := strings.Split(email, "@")
	username, domain := components[0], components[1]
	accessString := "changePassword?token=" + token +
		"&username=" + username + "&domain=" + domain

	message := []byte("From: " + from + "\r\n" +
		"To: " + email + "\r\n" +
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
	log.Print("INFO: Sent OTL to " + email)
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

func emailEnabled(email string) bool {
	components := strings.Split(email, "@")
	username, domain := components[0], components[1]

	var db = connectToDatabase()

	var enabled bool
	if err := db.QueryRow("SELECT (enabled = true) FROM accounts WHERE username = $1 AND domain = $2;",
		username, domain).Scan(&enabled); err != nil {
		if err == sql.ErrNoRows {
			db.Close()
			log.Print("INFO: Unknown email address: " + username + "@" + domain)
			return false
		}
	}
	db.Close()

	if enabled {
		log.Print("INFO: " + username + "@" + domain + " successfully validated")
		return true
	}
	return false
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

	if emailEnabled(email) {
		lastEmailSent = time.Now()
		go sendOneTimeLink(email)
	}
}

func passwordChangeHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	username := r.URL.Query().Get("username")
	domain := r.URL.Query().Get("domain")

	data := url{
		Token:    token,
		Username: username,
		Domain:   domain,
	}

	var url = "changePassword?token=" + token +
		"&username=" + username +
		"&domain=" + domain

	_, ok := oneTimeURLs.m[url]
	if !ok {
		fmt.Fprintf(w, "Link expired")
		return
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
		if os.Args[1] == "--version" {
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
			os.Exit(0)
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
			if time.Now().Sub(v) > (10 * time.Minute) {
				deleteFromHashMap(oneTimeURLs.m, k)
				log.Print("INFO: Deleted expired route " + k + " from map")
			}
		}
	}
}
