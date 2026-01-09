package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// -------------------- Helpers --------------------

// Clear DB table before each test
func clearDB() {
	db.Exec("DELETE FROM feedback")
}

// -------------------- Web Handlers Tests --------------------

func TestWeb_LoginFlow(t *testing.T) {
	initDB()
	sessions = map[string]string{} // clear sessions
	clearDB()

	// GET /login should return 200 OK
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	showLogin(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /login, got %d", w.Result().StatusCode)
	}

	// POST /login with valid credentials
	form := strings.NewReader("username=alex&password=password123")
	req = httptest.NewRequest(http.MethodPost, "/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handleLogin(w, req)

	if w.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 SeeOther after login, got %d", w.Result().StatusCode)
	}

	// Check if session cookie was set
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "session" && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected session cookie to be set after login")
	}
}

func TestWeb_SubmitFormFlow(t *testing.T) {
	initDB()
	sessions = map[string]string{}
	clearDB()

	// Setup session
	sessionID := createSession("alex")
	sessions[sessionID] = "alex"
	cookie := &http.Cookie{Name: "session", Value: sessionID}

	// POST /submit form
	form := strings.NewReader("rating=7&explanation=yes&feelings=good&doctor=Dr. Smith")
	req := httptest.NewRequest(http.MethodPost, "/submit", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()

	submitForm(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after form submit, got %d", w.Result().StatusCode)
	}

	// Check that summary page content includes username
	if !strings.Contains(w.Body.String(), "alex") {
		t.Fatal("expected summary page to include username")
	}
}

func TestWeb_AdminView(t *testing.T) {
	initDB()

	// Clear previous test data
	db.Exec(`DELETE FROM feedback`)

	// Insert multiple realistic feedback entries with only Dr. Johnson, Dr. Lee, Dr. Smith
	testData := []Feedback{
		{"alice", "Dr. Smith", 8, "Yes", "Feeling happy"},
		{"bob", "Dr. Johnson", 6, "No", "Feeling okay"},
		{"carol", "Dr. Lee", 9, "Yes", "Feeling great"},
		{"dave", "Dr. Smith", 5, "Unclear / Mixed", "Feeling unsure"},
		{"eve", "Dr. Johnson", 7, "Yes", "Feeling good"},
		{"frank", "Dr. Lee", 10, "Yes", "Feeling excellent"},
		{"grace", "Dr. Smith", 4, "No", "Feeling bad"},
		{"heidi", "Dr. Johnson", 6, "Yes", "Feeling fine"},
		{"ivan", "Dr. Lee", 8, "Yes", "Feeling happy"},
		{"judy", "Dr. Smith", 7, "No", "Feeling okay"},
	}

	for _, f := range testData {
		db.Exec(`INSERT INTO feedback (username, doctor_name, rating, explanation_clear, feelings)
			VALUES (?, ?, ?, ?, ?)`,
			f.Username, f.DoctorName, f.Rating, f.ExplanationClear, f.Feelings)
	}

	// Setup admin session
	sessionID := createSession("admin")
	sessions[sessionID] = "admin"
	cookie := &http.Cookie{Name: "session", Value: sessionID}

	req := httptest.NewRequest(http.MethodGet, "/admin/feedback", nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()

	adminFeedback(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for admin feedback, got %d", w.Result().StatusCode)
	}

	body := w.Body.String()

	// Check for the correct table headers
	headers := []string{"User", "Doctor", "Rating", "Explanation", "Feelings"}
	for _, h := range headers {
		if !strings.Contains(body, h) {
			t.Fatalf("expected header %q in admin page", h)
		}
	}

	// Check that all 10 rows are present
	for _, f := range testData {
		if !strings.Contains(body, f.Username) {
			t.Fatalf("expected username %q in admin page", f.Username)
		}
		if !strings.Contains(body, f.DoctorName) {
			t.Fatalf("expected doctor %q in admin page", f.DoctorName)
		}
	}
}

// -------------------- API Tests --------------------
// (Leave commented out; can enable after JWT testing)
/*
func TestAPI_Login(t *testing.T) {
	initDB()
	payload := `{"username":"alex","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	apiLogin(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
}

func TestAPI_Feedback(t *testing.T) {
	initDB()
	// implement JWT feedback test if needed
}
*/
