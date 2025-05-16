package main

import (
	"fmt"
	"net/http"
	"strings"
	"html/template"
	"context"
	"log"
	"golang.org/x/crypto/bcrypt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var collection *mongo.Collection

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
	if(r.Method == http.MethodPost) {
		err := r.ParseForm()
		if(err != nil) {
			http.Error(w, "Err", 400)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		var user struct {
			Username string `bson:"username"`
			Password string `bson:"password"`
		}

		err = collection.FindOne(context.TODO(), map[string]interface{}{
			"username": username,
		}).Decode(&user)

		if(err != nil) {
			http.Error(w, "Korisnik nije pronađen", 401)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		
		if(err != nil) {
			http.Error(w, "Pogrešna lozinka", 401)
			return
		}

		fmt.Fprintln(w, "Uspešna prijava!")
		return
	}

	renderTemplate(w, "login")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Err", 400)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		phoneNumber := r.FormValue("phoneNumber")
		email := r.FormValue("email")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error with hashing password.", 500)
			return
		}

		user := map[string]interface{}{
			"username": username,
			"password": string(hashedPassword),
			"email": email,
			"phone-number": phoneNumber,
		}

		_, err = collection.InsertOne(context.TODO(), user)
		if err != nil {
			http.Error(w, "Error with register form.", 500)
			return
		}

		fmt.Fprintln(w, "Register Successfull.")
		return
	}

	renderTemplate(w, "register")
}

func uploadHandler(w http.ResponseWriter, r * http.Request) {
	renderTemplate(w, "upload")
}

func main() {
	client, _ := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	collection = client.Database("codehub").Collection("users")

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