from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

def init_db():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_attempts (
                user_id INTEGER,
                pyq_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, pyq_id),
                FOREIGN KEY (pyq_id) REFERENCES questions(id)
            )
        ''')
    with sqlite3.connect('contacts.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                subject TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    with sqlite3.connect('pyqs.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                exam TEXT,
                subject TEXT,
                year INTEGER,
                question_text TEXT,
                solution_text TEXT,
                pdf_link TEXT
            )
        ''')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            with sqlite3.connect('users.db') as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                              (username, email, hashed_password))
                conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            with sqlite3.connect('users.db') as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                user = cursor.fetchone()
                if user and check_password_hash(user[3], password):
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    flash('Login successful!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Invalid username or password.', 'danger')
        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        try:
            with sqlite3.connect('contacts.db') as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO contacts (name, email, subject, message) VALUES (?, ?, ?, ?)',
                              (name, email, subject, message))
                conn.commit()
            flash('Your message has been sent successfully!', 'success')
            return redirect(url_for('contact'))
        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'danger')
    return render_template('contact.html')

@app.route('/profile')
@login_required
def profile():
    try:
        with sqlite3.connect('users.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(DISTINCT pyq_id) as pyqs_attempted FROM user_attempts WHERE user_id = ?',
                          (session['user_id'],))
            pyqs_attempted = cursor.fetchone()['pyqs_attempted']
        return render_template('profile.html', username=session['username'], pyqs_attempted=pyqs_attempted)
    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'danger')
        return redirect(url_for('index'))

@app.route('/pyq', methods=['GET'])
@login_required
def pyq():
    exam = request.args.get('exam', '')
    subject = request.args.get('subject', '')
    year = request.args.get('year', '')

    query = 'SELECT id, exam, subject, year, question_text, solution_text, pdf_link FROM questions WHERE 1=1'
    params = []

    if exam:
        query += ' AND exam = ?'
        params.append(exam)
    if subject:
        query += ' AND subject = ?'
        params.append(subject)
    if year:
        query += ' AND year = ?'
        params.append(int(year))

    try:
        with sqlite3.connect('pyqs.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            questions = cursor.fetchall()

            cursor.execute('SELECT DISTINCT exam FROM questions')
            exams = [row[0] for row in cursor.fetchall()]
            cursor.execute('SELECT DISTINCT subject FROM questions')
            subjects = [row[0] for row in cursor.fetchall()]
            cursor.execute('SELECT DISTINCT year FROM questions')
            years = [row[0] for row in cursor.fetchall()]

        return render_template('pyq.html', questions=questions, exams=exams, subjects=subjects, years=years,
                              selected_exam=exam, selected_subject=subject, selected_year=year)
    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'danger')
        return redirect(url_for('index'))

@app.route('/track_pyq', methods=['POST'])
@login_required
def track_pyq():
    pyq_id = request.json.get('pyq_id')
    user_id = session['user_id']
    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT OR IGNORE INTO user_attempts (user_id, pyq_id) VALUES (?, ?)', (user_id, pyq_id))
            conn.commit()
            print(f"Tracking PYQ for user ID: {user_id}")
            print("PYQ attempt recorded")
            return jsonify({'status': 'success'})
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/videos')
def videos():
    return render_template('videos.html')

if __name__ == '__main__':
    if not os.path.exists('users.db'):
        init_db()
    app.run(debug=True)