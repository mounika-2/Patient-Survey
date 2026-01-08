package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// -------------------- Types --------------------

type User struct {
	Password string
	Role     string // "user" or "admin"
}

type SurveyData struct {
	PatientFirstName string
	DoctorName       string
	Diagnosis        string
	Rating           int
	ExplanationClear string
	Feelings         string
}

type Feedback struct {
	Username         string
	DoctorName       string
	Rating           int
	ExplanationClear string
	Feelings         string
}

// -------------------- Globals --------------------

var users = map[string]User{
	"alex":  {Password: "password123", Role: "user"},
	"admin": {Password: "admin123", Role: "admin"},
}

var (
	formTmpl    = template.Must(template.ParseFiles("templates/form.html"))
	summaryTmpl = template.Must(template.ParseFiles("templates/summary.html"))
	loginTmpl   = template.Must(template.ParseFiles("templates/login.html"))
	adminTmpl   = template.Must(template.ParseFiles("templates/admin.html"))

	db       *sql.DB
	sessions = map[string]string{} // sessionID -> username
)

// -------------------- Main --------------------

func main() {
	if err := initDB(); err != nil {
		panic(err)
	}

	fmt.Println("Server running at http://localhost:8080")
	http.ListenAndServe(":8080", routes())
}

// -------------------- Routes --------------------

func routes() http.Handler {
	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Web pages
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handleLogin(w, r)
		} else {
			showLogin(w, r)
		}
	})
	mux.HandleFunc("/", showForm)
	mux.HandleFunc("/submit", submitForm)
	mux.HandleFunc("/logout", logout)
	mux.HandleFunc("/admin/feedback", adminFeedback)
	mux.HandleFunc("/summary", showSummary)

	return mux
}

// -------------------- Web Handlers --------------------

func showLogin(w http.ResponseWriter, r *http.Request) {
	loginTmpl.Execute(w, nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := users[username]
	if !ok || user.Password != password {
		// Instead of http.Error, render login template with error
		loginTmpl.Execute(w, struct{ Error string }{
			Error: "Login username and password do not match, try again",
		})
		return
	}

	sessionID := createSession(username)
	sessions[sessionID] = username

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
	})

	if user.Role == "admin" {
		http.Redirect(w, r, "/admin/feedback", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func showForm(w http.ResponseWriter, r *http.Request) {
	username, ok := getUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if users[username].Role == "admin" {
		http.Redirect(w, r, "/admin/feedback", http.StatusSeeOther)
		return
	}

	formTmpl.Execute(w, struct{ Username string }{Username: username})
}

func submitForm(w http.ResponseWriter, r *http.Request) {
	username, ok := getUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Validate rating
	rating, err := strconv.Atoi(r.FormValue("rating"))
	if err != nil || rating < 1 || rating > 10 {
		http.Error(w, "Rating must be a number between 1 and 10", http.StatusBadRequest)
		return
	}

	// Validate explanation
	explanation := normalizeYesNo(r.FormValue("explanation"))
	if explanation == "" {
		http.Error(w, "Explanation must be selected", http.StatusBadRequest)
		return
	}

	// Validate feelings
	feelings := strings.TrimSpace(r.FormValue("feelings"))
	if len(feelings) == 0 || len(feelings) > 500 {
		http.Error(w, "Please describe your feelings (1-500 characters)", http.StatusBadRequest)
		return
	}

	doctor := strings.TrimSpace(r.FormValue("doctor"))
	if doctor == "" {
		http.Error(w, "Doctor must be selected", http.StatusBadRequest)
		return
	}

	// Insert feedback
	_, err = db.Exec(
		`INSERT INTO feedback (username, doctor_name, rating, explanation_clear, feelings)
		 VALUES (?, ?, ?, ?, ?)`,
		username,
		doctor,
		rating,
		explanation,
		feelings,
	)
	if err != nil {
		http.Error(w, "Failed to save feedback", http.StatusInternalServerError)
		return
	}

	// Show summary
	data := SurveyData{
		PatientFirstName: username,
		DoctorName:       doctor,
		Diagnosis:        "Asthma",
		Rating:           rating,
		ExplanationClear: explanation,
		Feelings:         feelings,
	}

	summaryTmpl.Execute(w, data)
}

func showSummary(w http.ResponseWriter, r *http.Request) {
	username, ok := getUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var f Feedback
	row := db.QueryRow(
		`SELECT doctor_name, rating, explanation_clear, feelings
		FROM feedback
		WHERE username = ?
		ORDER BY created_at DESC
		LIMIT 1`, username)
	err := row.Scan(&f.DoctorName, &f.Rating, &f.ExplanationClear, &f.Feelings)
	if err != nil {
		http.Error(w, "No feedback found", http.StatusNotFound)
		return
	}

	data := SurveyData{
		PatientFirstName: username,
		DoctorName:       f.DoctorName,
		Diagnosis:        "Asthma",
		Rating:           f.Rating,
		ExplanationClear: f.ExplanationClear,
		Feelings:         f.Feelings,
	}

	summaryTmpl.Execute(w, data)
}

func logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(sessions, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func adminFeedback(w http.ResponseWriter, r *http.Request) {
	username, ok := getUserFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if users[username].Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Get doctor filter
	doctorFilter := strings.TrimSpace(r.URL.Query().Get("doctor"))

	var rows *sql.Rows
	var err error
	if doctorFilter != "" {
		rows, err = db.Query(
			`SELECT username, doctor_name, rating, explanation_clear, feelings
			 FROM feedback
			 WHERE LOWER(doctor_name) = LOWER(?)
			 ORDER BY created_at DESC`, doctorFilter)
	} else {
		rows, err = db.Query(
			`SELECT username, doctor_name, rating, explanation_clear, feelings
			 FROM feedback
			 ORDER BY created_at DESC`)
	}
	if err != nil {
		http.Error(w, "Failed to load feedback", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var allFeedback []Feedback
	for rows.Next() {
		var f Feedback
		if err := rows.Scan(&f.Username, &f.DoctorName, &f.Rating, &f.ExplanationClear, &f.Feelings); err != nil {
			http.Error(w, fmt.Sprintf("Scan failed: %v", err), http.StatusInternalServerError)
			return
		}
		allFeedback = append(allFeedback, f)
	}

	adminTmpl.Execute(w, struct {
		Feedback []Feedback
		Filter   string
	}{
		Feedback: allFeedback,
		Filter:   doctorFilter,
	})
}

// -------------------- Helpers --------------------

func getUserFromRequest(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("session")
	if err != nil {
		return "", false
	}
	username, ok := sessions[cookie.Value]
	return username, ok
}

func createSession(username string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func normalizeYesNo(input string) string {
	switch input {
	case "yes":
		return "Yes"
	case "no":
		return "No"
	default:
		return "Unclear / Mixed"
	}
}

func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "survey.db")
	if err != nil {
		return err
	}

	query := `
	CREATE TABLE IF NOT EXISTS feedback (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT,
		doctor_name TEXT,
		rating INTEGER,
		explanation_clear TEXT,
		feelings TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = db.Exec(query)
	return err
}
