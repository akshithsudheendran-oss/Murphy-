# Murphy — Web Vulnerability Scanner

**Murphy** is a lightweight, automated Dynamic Application Security Testing (DAST) scanner built with Python and Flask. It runs five independent security checks against a target URL, saves the findings to a MySQL database, and generates a downloadable PDF report.

This project was built as a final-year BCA project.

## Features

Murphy runs the following modules in sequence:

1. **Security Headers** — Checks for missing HSTS, CSP, X-Frame-Options, etc.
2. **SQL Injection (SQLi)** — Detects error-based and boolean-based blind SQLi.
3. **Cross-Site Scripting (XSS)** — Detects reflected XSS via unescaped output.
4. **Port Scanner** — Uses raw TCP sockets to check for exposed ports (e.g., MySQL, FTP).
5. **Admin Finder** — Probes common sensitive paths (e.g., `/admin`, `/.env`, `/phpmyadmin`).

## Technology Stack
- **Backend:** Python 3, Flask
- **Database:** MySQL
- **Scanners:** `requests`, `socket` (built-in)
- **Reports:** ReportLab (PDF generation)
- **Frontend:** HTML, CSS, Vanilla JS (Jinja2 templates)

## Ethical Disclaimer
This tool is for **educational and authorized testing only**. Scanning websites without explicit permission is illegal under the IT Act 2000 and similar laws worldwide.

---

## Setup & Installation

### 1. Prerequisites
- Python 3.10+
- MySQL (XAMPP is recommended, as it includes PHP/Apache for the test target)
- Git

### 2. Clone the repository

git clone https://github.com/akshithsudheendran-oss/murphy.git
cd murphy



### 3. Virtual Environment & Dependencies
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
# source venv/bin/activate

pip install -r requirements.txt



### 4. Database Setup
Open MySQL (or phpMyAdmin).

Create a database named murphy_db.

Import the schema:
mysql -u root -p murphy_db < database/schema.sql
(Or paste the contents of database/schema.sql into phpMyAdmin).



### 5. Environment Variables
Copy .env.example to .env and fill in your MySQL root password:

DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password_here
DB_NAME=murphy_db
SECRET_KEY=super_secret_random_string



### 6. Test Target Setup (DVWA)
To see the scanner actually find vulnerabilities, you need a vulnerable target.

Download DVWA and place it in your web server's document root (e.g., C:\xampp\htdocs\dvwa).

Open http://localhost/dvwa/setup.php and click Create / Reset Database.

Log in (admin / password) and set DVWA Security to Low.

Ensure pdo_mysql is enabled in your php.ini and restart Apache.


### 7. Run the App
python app.py
Open url in your browser. Register an account, log in, and scan http://localhost/dvwa.



Project Structure

murphy/
├── app.py                 # Flask routes & API
├── config.py              # Environment variables loader
├── database/              # MySQL connection & schema
├── models/                # User and Scan database logic
├── scanner/               # The 5 vulnerability scanners
├── reports/               # PDF generator (ReportLab)
├── templates/             # Jinja2 HTML files
└── static/                # CSS and JS
