package main

import (
	"crypto/sha1"
	"fmt"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type user struct {
	UserName string
	Password []byte
	First    string
	Last     string
}

type session struct {
	un           string
	lastActivity time.Time
}

var tpl *template.Template
var dbUsers = map[string]user{}           // user ID, user
var dbSessions = make(map[string]session) // session ID, user ID
var dbSessionCleaned time.Time

const sessionLife int = 60

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	bs, _ := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.MinCost)
	dbUsers["account@gmail.com"] = user{"account@gmail.com", bs, "Vincent", "Zhu"}
	dbSessionCleaned = time.Now()
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("./public"))))
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, req *http.Request) {
	logged := loggedIn(req)

	if req.Method == http.MethodPost {
		mf, fh, err := req.FormFile("newfile")
		if err != nil {
			fmt.Println(err)
		}
		defer mf.Close()
		// create SHA
		ext := strings.Split(fh.Filename, ".")[1]
		h := sha1.New()
		io.Copy(h, mf)
		fname := fmt.Sprintf("%x", h.Sum(nil)) + "." + ext

		wd, err := os.Getwd()
		if err != nil {
			fmt.Println(err)
		}
		path := filepath.Join(wd, "public", "pics", fname)
		nf, err := os.Create(path)
		if err != nil {
			fmt.Println(err)
			fmt.Println("duplicate files")
		}
		defer nf.Close()
		mf.Seek(0, 0)
		io.Copy(nf, mf)
	}

	wd, _ := os.Getwd()
	picNames, _ := filepath.Glob(wd + "/public/pics/*.jpg")
	for idx, _ := range picNames {
		picNames[idx] = filepath.Base(picNames[idx])
	}

	info := struct {
		Login bool //captialize if you want access from outside
		Pics  []string
	}{
		logged,
		picNames,
	}
	tpl.ExecuteTemplate(w, "index.gohtml", info)
}

func register(w http.ResponseWriter, req *http.Request) {
	if loggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	var u user
	if req.Method == http.MethodPost {
		un := req.FormValue("username")
		p := req.FormValue("password")
		f := req.FormValue("firstname")
		l := req.FormValue("lastname")

		if _, ok := dbUsers[un]; ok {
			http.Error(w, "username already taken", http.StatusForbidden)
			return
		}
		// create session
		sid := uuid.NewV4()
		cookie := &http.Cookie{
			Name:  "session",
			Value: sid.String(),
		}
		http.SetCookie(w, cookie)
		dbSessions[cookie.Value] = session{un, time.Now()}
		//store user data
		bs, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.MinCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		u = user{un, bs, f, l}
		dbUsers[un] = u
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "signup.gohtml", u)
}

func login(w http.ResponseWriter, req *http.Request) {
	if loggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	if req.Method == http.MethodPost {
		un := req.FormValue("username")
		p := req.FormValue("password")
		u, ok := dbUsers[un]
		if !ok {
			http.Error(w, "Username and/or password do not match.", http.StatusForbidden)
			return
		}
		// check the password
		err := bcrypt.CompareHashAndPassword(u.Password, []byte(p))
		if err != nil {
			http.Error(w, "Username and/or password do not match.", http.StatusForbidden)
			return
		}
		//create session
		sid := uuid.NewV4()
		c := &http.Cookie{
			Name:  "session",
			Value: sid.String(),
		}
		c.MaxAge = sessionLife
		http.SetCookie(w, c)
		dbSessions[c.Value] = session{un, time.Now()}
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(w, "signup.gohtml", nil)
}

func logout(w http.ResponseWriter, req *http.Request) {
	if !loggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	c, _ := req.Cookie("session")
	delete(dbSessions, c.Value)
	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)
	if time.Now().Sub(dbSessionCleaned) > (time.Second * 60) {
		go cleanSessions()
	}
	http.Redirect(w, req, "/login", http.StatusSeeOther)
}
