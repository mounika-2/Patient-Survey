package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// -------------------- Web Handlers Tests --------------------

func TestWeb_LoginFlow(t *testing.T) {
	initDB()

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

	// Setup session
	sessionID := createSession("alex")
	sessions[sessionID] = "alex"
	cookie := &http.Cookie{Name: "session", Value: sessionID}

	form := strings.NewReader("rating=7&explanation=yes&feelings=good")
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

	// Page should include table headers
	body := w.Body.String()
	if !strings.Contains(body, "Username") || !strings.Contains(body, "Rating") {
		t.Fatal("admin page missing expected table headers")
	}
}

// -------------------- API Tests --------------------

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

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["status"] != "ok" || body["role"] != "user" {
		t.Fatal("unexpected response body from /api/login")
	}
}

func TestAPI_Feedback(t *testing.T) {
	initDB()

	// Setup session
	sessionID := createSession("alex")
	sessions[sessionID] = "alex"
	cookie := &http.Cookie{Name: "session", Value: sessionID}

	// Valid feedback
	payload := `{"rating":8,"explanation":"yes","feelings":"happy"}`
	req := httptest.NewRequest(http.MethodPost, "/api/feedback", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()

	apiSubmitFeedback(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body["status"] != "saved" {
		t.Fatal("expected status saved in API response")
	}

	// Invalid rating
	payload = `{"rating":-1,"explanation":"yes","feelings":"sad"}`
	req = httptest.NewRequest(http.MethodPost, "/api/feedback", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()

	apiSubmitFeedback(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 BadRequest for invalid rating, got %d", w.Result().StatusCode)
	}

	// Unauthorized (no session)
	payload = `{"rating":5,"explanation":"no","feelings":"meh"}`
	req = httptest.NewRequest(http.MethodPost, "/api/feedback", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	apiSubmitFeedback(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing session, got %d", w.Result().StatusCode)
	}
}

// -------------------- Helpers --------------------

func init() {
	// Clear sessions map before tests
	sessions = map[string]string{}
}
