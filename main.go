package main

import (
	"fmt"
	"net/http"
	"strings"
	"html/template"
)

func renderTemplate(w http.ResponseWriter, tmpl string) {
	t, err := template.ParseFiles("templates/" + tmpl + ".html")
	if err != nil {
		http.Error(w, "Error", 500)
		return
	}
	t.Execute(w, nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "index")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "login")
}

func registerHandler(w http.ResponseWriter, r * http.Request) {
	renderTemplate(w, "register")
}

func uploadHandler(w http.ResponseWriter, r * http.Request) {
	renderTemplate(w, "upload")
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/upload", uploadHandler)

	port := 8080
	host := "127.0.0.1"
	msg := `

    [!] http://{{host}}:{{port}}/index
    [!] http://{{host}}:{{port}}/login
    [!] http://{{host}}:{{port}}/register
    [!] http://{{host}}:{{port}}/upload
	
	`
	
	msg = strings.ReplaceAll(msg, "{{host}}", host)
	msg = strings.ReplaceAll(msg, "{{port}}", fmt.Sprintf("%d", port))

	fmt.Printf("[+] Server has started on %s:%d\n", host, port)
	fmt.Println(msg)

	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}