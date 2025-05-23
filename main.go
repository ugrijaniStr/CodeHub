package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"time"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var collection *mongo.Collection
var postsCollection *mongo.Collection

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("templates/" + tmpl + ".html")
	if err != nil {
		http.Error(w, "Template error", 500)
		return
	}
	t.Execute(w, data)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "index", nil)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := struct {
		Username string
	}{
		Username: cookie.Value,
	}

	renderTemplate(w, "dashboard", data)
}

func accountSettingsHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("username")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	currentUsername := cookie.Value

	switch r.Method {
	case http.MethodGet:
		var user struct {
			Username    string `bson:"username"`
			Description string `bson:"description"`
			Color       string `bson:"color-name"`
		}
		err := collection.FindOne(context.TODO(), map[string]interface{}{
			"username": currentUsername,
		}).Decode(&user)
		if err != nil {
			http.Error(w, "User not found", http.StatusInternalServerError)
			return
		}

		renderTemplate(w, "accountSettings", user)

	case http.MethodPost:
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		newUsername := r.FormValue("username")
		newDescription := r.FormValue("description")
		newUserColor := r.FormValue("color")

		if newUsername == "" {
			http.Error(w, "Username cannot be empty", http.StatusBadRequest)
			return
		}

		filter := map[string]interface{}{
			"username": currentUsername,
		}
		update := map[string]interface{}{
			"$set": map[string]interface{}{
				"username":    newUsername,
				"description": newDescription,
				"color-name":  newUserColor,
			},
		}

		result, err := collection.UpdateOne(context.TODO(), filter, update)
		if err != nil || result.MatchedCount == 0 {
			http.Error(w, "Update failed", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "username",
			Value: newUsername,
			Path:  "/",
		})

		data := struct {
			Username    string
			Description string
			Color       string
			Success     bool
			Message     string
		}{
			Username:    newUsername,
			Description: newDescription,
			Color:       newUserColor,
			Success:     true,
			Message:     "Success",
		}
		renderTemplate(w, "accountSettings", data)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Form parse error", 400)
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

		if err != nil {
			http.Error(w, "User not found", 401)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Error(w, "Wrong username or password", 401)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "username",
			Value: username,
			Path:  "/",
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "login", nil)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Form parse error", 400)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		phoneNumber := r.FormValue("phoneNumber")
		email := r.FormValue("email")

		filter := map[string]interface{}{
			"$or": []interface{}{
				map[string]interface{}{"username": username},
				map[string]interface{}{"email": email},
			},
		}

		var existingUser struct {
			Username string `bson:"username"`
			Email    string `bson:"email"`
		}

		err = collection.FindOne(context.TODO(), filter).Decode(&existingUser)
		if err == nil {
			http.Error(w, "Username or email already exists", http.StatusConflict)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Password hashing error", 500)
			return
		}

		user := map[string]interface{}{
			"username":     username,
			"password":     string(hashedPassword),
			"email":        email,
			"phone-number": phoneNumber,
			"color-name":   "#000000",
			"pfp":          "",
			"description":  "",
		}

		_, err = collection.InsertOne(context.TODO(), user)
		if err != nil {
			http.Error(w, "Registration error", 500)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "username",
			Value: username,
			Path:  "/",
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "register", nil)
}

func uploadPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "err with form", http.StatusBadRequest)
			return
		}

		title := r.FormValue("title")
		description := r.FormValue("description")

		if title == "" || description == "" {
			http.Error(w, "required", http.StatusBadRequest)
			return
		}

		cookie, err := r.Cookie("username")
		if err != nil {
			http.Error(w, "You are not logged in account.", http.StatusUnauthorized)
			return
		}

		var user struct {
			ID       primitive.ObjectID `bson:"_id"`
			Username string             `bson:"username"`
		}

		err = collection.FindOne(context.TODO(), bson.M{"username": cookie.Value}).Decode(&user)
		if err != nil {
			http.Error(w, "User has not found", http.StatusInternalServerError)
			return
		}

		post := bson.M{
			"title":       title,
			"description": description,
			"author_id":   user.ID,
			"created_at":  time.Now(),
		}

		_, err = postsCollection.InsertOne(context.TODO(), post)
		if err != nil {
			http.Error(w, "err", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "upload", nil)
}

func listPostsHandler(w http.ResponseWriter, r *http.Request) {
	cursor, err := postsCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch posts", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	type PostWithAuthor struct {
		Title     string
		Username  string
		CreatedAt string
	}

	var posts []PostWithAuthor

	for cursor.Next(context.TODO()) {
		var post struct {
			Title     string             `bson:"title"`
			AuthorID  primitive.ObjectID `bson:"author_id"`
			CreatedAt time.Time          `bson:"created_at"`
		}

		if err := cursor.Decode(&post); err != nil {
			continue
		}

		var user struct {
			Username string `bson:"username"`
		}
		err = collection.FindOne(context.TODO(), bson.M{"_id": post.AuthorID}).Decode(&user)
		if err != nil {
			continue
		}

		posts = append(posts, PostWithAuthor{
			Title:     post.Title,
			Username:  user.Username,
			CreatedAt: post.CreatedAt.Format("02.01.2006 15:04"),
		})
	}

	renderTemplate(w, "list", struct {
		Posts []PostWithAuthor
	}{Posts: posts})
}


func postDetailHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/user/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}

	username := parts[0]
	title := parts[1]

	var user struct {
		ID       primitive.ObjectID `bson:"_id"`
		Username string             `bson:"username"`
	}
	err := collection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	var post struct {
		Title       string    `bson:"title"`
		Description string    `bson:"description"`
		CreatedAt   time.Time `bson:"created_at"`
	}
	err = postsCollection.FindOne(context.TODO(), bson.M{
		"author_id": user.ID,
		"title":     title,
	}).Decode(&post)
	if err != nil {
		http.Error(w, "Post not found", http.StatusNotFound)
		return
	}

	data := struct {
		Username    string
		Title       string
		Description string
		CreatedAt   string
	}{
		Username:    username,
		Title:       post.Title,
		Description: post.Description,
		CreatedAt:   post.CreatedAt.Format("02.01.2006 15:04"),
	}

	renderTemplate(w, "postDetail", data)
}

func main() {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal("MongoDB client error:", err)
	}

	err = client.Connect(context.TODO())
	if err != nil {
		log.Fatal("MongoDB connection error:", err)
	}

	collection = client.Database("codehub").Collection("users")
	postsCollection = client.Database("codehub").Collection("posts")

	fs := http.FileServer(http.Dir("templates/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/upload", uploadPostHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/accountSettings", accountSettingsHandler)
	http.HandleFunc("/list", listPostsHandler)
	http.HandleFunc("/user/", postDetailHandler)

	port := 8080
	host := "127.0.0.1"

	msg := `
		[!] http://{{host}}:{{port}}/index
		[!] http://{{host}}:{{port}}/login
		[!] http://{{host}}:{{port}}/register
		[!] http://{{host}}:{{port}}/dashboard
		[!] http://{{host}}:{{port}}/upload
		[!] http://{{host}}:{{port}}/accountSettings
		[!] http://{{host}}:{{port}}/list
		`

	msg = strings.ReplaceAll(msg, "{{host}}", host)
	msg = strings.ReplaceAll(msg, "{{port}}", fmt.Sprintf("%d", port))

	fmt.Printf("[+] Server started on %s:%d\n", host, port)
	fmt.Println(msg)

	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}
