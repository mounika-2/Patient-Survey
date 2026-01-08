🏥 Patient Feedback Web Application (Go)

This project is a Go-based web application that allows patients to submit feedback about their doctor visit and allows administrators to view and filter all feedback.

It demonstrates:

Session-based authentication

Role-based access (user vs admin)

SQLite persistence

Server-side + client-side validation

HTML templates with Go

Admin data filtering

📁 Project Structure
.
├── main.go
├── survey.db
├── templates/
│   ├── login.html
│   ├── form.html
│   ├── summary.html
│   └── admin.html
├── static/
│   ├── app.css
│   └── style.css
├── main_test.go
└── README.md

🧠 Application Overview
Users

Regular users can log in and submit feedback

Admins can view and filter all submitted feedback

Authentication

Session-based authentication using cookies

In-memory session storage

Two roles:

user

admin

📄 File Breakdown
main.go

The core application file.

Handles:

HTTP routing

User authentication and session management

Feedback submission

Admin filtering logic

Database initialization

Key responsibilities:

Defines all HTTP handlers (/login, /submit, /admin/feedback, etc.)

Validates user input

Stores and retrieves feedback from SQLite

Enforces role-based access

templates/login.html

Login page template.

Features:

Username/password login form

Inline validation message for incorrect credentials

Styled, centered login card

Used by:

showLogin

handleLogin

templates/form.html

Patient feedback form.

Features:

Dynamic doctor selection

Conversational question flow

Rating input (1–10)

Yes/No/Mixed explanation clarity

Feelings textarea with 250-character limit

Live character counter

Client-side validation

Used by:

showForm

submitForm

templates/summary.html

Feedback summary page shown after submission.

Features:

Narrative-style summary

Personalized with patient name, doctor name, diagnosis

Clear presentation of user responses

Option to submit another response or log out

Used by:

submitForm

showSummary

templates/admin.html

Admin-only feedback dashboard.

Features:

Table view of all feedback

Filter by doctor name

Case-insensitive filtering

Clean, modern UI

Empty-state messaging

Secure admin-only access

Used by:

adminFeedback

static/app.css

Primary styling for patient-facing pages.

Used by:

form.html

login.html

Defines:

Layout

Typography

Buttons

Form spacing

static/style.css

Styling for summary and admin views.

Used by:

summary.html

admin.html

Defines:

Tables

Containers

Admin UI elements

survey.db

SQLite database file.

Contains:

feedback table with:

username

doctor_name

rating

explanation clarity

feelings

timestamp

Created automatically on app startup.

main_test.go

Application test suite.

Covers:

Login flow

Form submission

Admin access control

Session handling

Validation logic

Uses:

httptest

In-memory session setup

🚀 Running the Application
Requirements

Go 1.20+

SQLite (via Go driver)

Start the server
go run main.go


Then open:

http://localhost:8080

🔐 Default Users
alex  / password123  (user)
admin / admin123     (admin)

🔎 Admin Features

View all submitted feedback

Filter feedback by doctor name

Secure admin-only access

Logout support

✅ Validation Summary
Field	Validation
Rating	Integer 1–10
Doctor	Required
Explanation	Yes / No / Mixed
Feelings	1–250 characters
Session	Required
🛠️ Future Enhancements (Optional)

Password hashing (bcrypt)

Persistent session storage

Pagination for admin table

Per-doctor analytics

CSRF protection

API endpoints for SPA/mobile use
