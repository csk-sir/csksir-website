from flask import Flask, render_template, request, jsonify, session, flash, redirect, url_for
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Replace with a secure key

# Database connection helper for users.db
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    return conn

# Database connection helper for csksir.db
def get_db():
    conn = sqlite3.connect('csksir.db')
    conn.row_factory = sqlite3.Row
    return conn

# Unified Login for Users and Admins
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        # Strip +91 if present in mobile number for user login
        identifier_cleaned = identifier.replace('+91', '') if identifier.startswith('+91') else identifier
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if the identifier matches an admin username
        cursor.execute('SELECT * FROM admins WHERE username = ?', (identifier,))
        admin = cursor.fetchone()
        
        if admin and check_password_hash(admin['password_hash'], password):
            session['admin_id'] = admin['id']
            session['is_admin'] = True  # Set is_admin to True for admins
            flash('Logged in as admin successfully!', 'success')
            conn.close()
            return redirect(url_for('admin_panel'))
        
        # If not an admin, check if the identifier matches a user's email or mobile number
        cursor.execute('SELECT * FROM users WHERE email = ? OR mobile_no = ?', (identifier_cleaned, identifier_cleaned))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['is_admin'] = False  # Explicitly set is_admin to False for regular users
            flash('Logged in successfully!', 'success')
            conn.close()
            return redirect(url_for('profile'))
        
        # If neither admin nor user, show error
        flash('Invalid email/mobile number or password.', 'danger')
        conn.close()
        return redirect(url_for('login'))
    
    return render_template('login.html')

# Logout (Handles both admin and user logout)
@app.route('/logout')
def logout():
    session.pop('admin_id', None)
    session.pop('user_id', None)
    session.pop('is_admin', None)  # Clear is_admin on logout
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

# Admin Panel (Protected Route)
@app.route('/admin')
def admin_panel():
    if 'admin_id' not in session:
        flash('Please log in to access the admin panel.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch all topics for all subjects
    cursor.execute('SELECT * FROM video_topics')
    topics = cursor.fetchall()
    
    # Fetch subtopics for each topic
    topics_with_subtopics = []
    for topic in topics:
        cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
        subtopics = cursor.fetchall()
        topic_dict = dict(topic)
        topic_dict['subtopics'] = subtopics
        topics_with_subtopics.append(topic_dict)
    
    conn.close()
    
    return render_template('admin.html', topics=topics_with_subtopics)

# Add Topic
@app.route('/admin/add_topic', methods=['POST'])
def admin_add_topic():
    if 'admin_id' not in session:
        flash('Please log in to access the admin panel.', 'danger')
        return redirect(url_for('login'))
    
    subject = request.form['subject']
    topic_id = request.form['topic_id']
    topic_name = request.form['topic_name']
    description = request.form['description']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO video_topics (subject, topic_id, topic_name, description)
                    VALUES (?, ?, ?, ?)''', (subject, topic_id, topic_name, description))
    conn.commit()
    conn.close()
    
    flash('Topic added successfully!', 'success')
    return redirect(url_for('admin_panel'))

# Edit Topic
@app.route('/admin/edit_topic/<int:topic_id>', methods=['GET', 'POST'])
def admin_edit_topic(topic_id):
    if 'admin_id' not in session:
        flash('Please log in to access the admin panel.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        subject = request.form['subject']
        topic_id_new = request.form['topic_id']
        topic_name = request.form['topic_name']
        description = request.form['description']
        
        cursor.execute('''UPDATE video_topics
                        SET subject = ?, topic_id = ?, topic_name = ?, description = ?
                        WHERE id = ?''', (subject, topic_id_new, topic_name, description, topic_id))
        conn.commit()
        conn.close()
        
        flash('Topic updated successfully!', 'success')
        return redirect(url_for('admin_panel'))
    
    cursor.execute('SELECT * FROM video_topics WHERE id = ?', (topic_id,))
    topic = cursor.fetchone()
    conn.close()
    
    if not topic:
        flash('Topic not found.', 'danger')
        return redirect(url_for('admin_panel'))
    
    return render_template('edit_topic.html', topic=topic)

# Delete Topic
@app.route('/admin/delete_topic/<int:topic_id>', methods=['POST'])
def admin_delete_topic(topic_id):
    if 'admin_id' not in session:
        flash('Please log in to access the admin panel.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Delete subtopics first (due to foreign key constraint)
    cursor.execute('DELETE FROM subtopics WHERE video_topic_id = ?', (topic_id,))
    # Delete topic
    cursor.execute('DELETE FROM video_topics WHERE id = ?', (topic_id,))
    
    conn.commit()
    conn.close()
    
    flash('Topic and its subtopics deleted successfully!', 'success')
    return redirect(url_for('admin_panel'))

# Add Subtopic
@app.route('/admin/add_subtopic/<int:topic_id>', methods=['POST'])
def admin_add_subtopic(topic_id):
    if 'admin_id' not in session:
        flash('Please log in to access the admin panel.', 'danger')
        return redirect(url_for('login'))
    
    name = request.form['subtopic_name']
    video_url = request.form['video_url']
    description = request.form['subtopic_description']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO subtopics (video_topic_id, name, video_url, description)
                    VALUES (?, ?, ?, ?)''', (topic_id, name, video_url, description))
    conn.commit()
    conn.close()
    
    flash('Subtopic added successfully!', 'success')
    return redirect(url_for('admin_panel'))

# Edit Subtopic
@app.route('/admin/edit_subtopic/<int:subtopic_id>', methods=['GET', 'POST'])
def admin_edit_subtopic(subtopic_id):
    if 'admin_id' not in session:
        flash('Please log in to access the admin panel.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form['subtopic_name']
        video_url = request.form['video_url']
        description = request.form['description']
        
        cursor.execute('''UPDATE subtopics
                        SET name = ?, video_url = ?, description = ?
                        WHERE id = ?''', (name, video_url, description, subtopic_id))
        conn.commit()
        conn.close()
        
        flash('Subtopic updated successfully!', 'success')
        return redirect(url_for('admin_panel'))
    
    cursor.execute('SELECT * FROM subtopics WHERE id = ?', (subtopic_id,))
    subtopic = cursor.fetchone()
    conn.close()
    
    if not subtopic:
        flash('Subtopic not found.', 'danger')
        return redirect(url_for('admin_panel'))
    
    return render_template('edit_subtopic.html', subtopic=subtopic)

# Delete Subtopic
@app.route('/admin/delete_subtopic/<int:subtopic_id>', methods=['POST'])
def admin_delete_subtopic(subtopic_id):
    if 'admin_id' not in session:
        flash('Please log in to access the admin panel.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM subtopics WHERE id = ?', (subtopic_id,))
    conn.commit()
    conn.close()
    
    flash('Subtopic deleted successfully!', 'success')
    return redirect(url_for('admin_panel'))

# Home Page welcome message
@app.route('/')
def index():
    first_name = None
    if 'user_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT full_name FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        if user and user['full_name']:
            # Extract the first name from full_name
            first_name = user['full_name'].split()[0] if user['full_name'].split() else user['full_name']
    
    return render_template('index.html', first_name=first_name)

# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        mobile = request.form['mobile']
        class_level = request.form['class']
        password = request.form['password']
        
        # Validate mobile number (10 digits)
        if not re.match(r'^\d{10}$', mobile):
            flash('Mobile number must be 10 digits.', 'danger')
            return redirect(url_for('register'))
        
        # Hash password using scrypt
        hashed_password = generate_password_hash(password, method='scrypt')
        
        # Check if email already exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Email already registered.', 'danger')
            conn.close()
            return redirect(url_for('register'))
        
        # Insert into database
        try:
            cursor.execute('INSERT INTO users (full_name, email, mobile_no, current_class, password) VALUES (?, ?, ?, ?, ?)',
                          (name, email, mobile, class_level, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'Database error: {str(e)}', 'danger')
            print(f"Database error: {str(e)}")  # Debug log
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template('register.html')

# Profile Page
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'danger')
        return redirect(url_for('login'))

    # Connect to users.db for user details
    conn_users = get_db_connection()
    cursor_users = conn_users.cursor()

    # Fetch user details
    cursor_users.execute('SELECT full_name, current_class, email, mobile_no, dob FROM users WHERE id = ?', (session['user_id'],))
    user = cursor_users.fetchone()

    # Fetch progress reports (keeping this for compatibility, though we'll replace it in the template)
    cursor_users.execute('SELECT subject, score, test_date, total_marks FROM progress_reports WHERE user_id = ?', (session['user_id'],))
    progress_reports = cursor_users.fetchall()

    conn_users.close()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    # Convert user tuple to dict
    user_data = {
        'full_name': user['full_name'],
        'current_class': user['current_class'],
        'email': user['email'],
        'mobile_no': user['mobile_no'],
        'dob': user['dob']
    }

    # Convert progress reports to list of dicts
    progress_data = [
        {
            'subject': report['subject'],
            'score': report['score'],
            'test_date': report['test_date'],
            'total_marks': report['total_marks'],
            'percentage': (report['score'] / report['total_marks'] * 100) if report['total_marks'] != 0 else 0
        }
        for report in progress_reports
    ]

    # Connect to csksir.db for attempted and bookmarked questions
    conn_questions = get_db()
    
    # Fetch attempted questions
    attempted_questions = conn_questions.execute('''SELECT q.* FROM questions q
                                                  JOIN user_attempts ua ON q.id = ua.question_id
                                                  WHERE ua.user_id = ?''',
                                                (session['user_id'],)).fetchall()

    # Fetch bookmarked questions
    bookmarked_questions = conn_questions.execute('''SELECT q.* FROM questions q
                                                    JOIN bookmarks b ON q.id = b.question_id
                                                    WHERE b.user_id = ?''',
                                                 (session['user_id'],)).fetchall()

    # Overall Performance for Progress Report
    total_attempts = conn_questions.execute(
        "SELECT COUNT(*) FROM user_attempts WHERE user_id = ?",
        (session['user_id'],)
    ).fetchone()[0]

    correct_attempts = conn_questions.execute(
        "SELECT COUNT(*) FROM user_attempts ua JOIN questions q ON ua.question_id = q.id "
        "WHERE ua.user_id = ? AND ua.selected_option = q.correct_option_index",
        (session['user_id'],)
    ).fetchone()[0]

    overall_accuracy = (correct_attempts / total_attempts * 100) if total_attempts > 0 else 0.0

    # Subject-Wise Performance
    subjects = ['Chemistry', 'Physics', 'Botany', 'Zoology']
    subject_performance = {}
    for subject in subjects:
        subject_attempts = conn_questions.execute(
            "SELECT COUNT(*) FROM user_attempts ua JOIN questions q ON ua.question_id = q.id "
            "WHERE ua.user_id = ? AND q.subject = ?",
            (session['user_id'], subject)
        ).fetchone()[0]
        subject_correct = conn_questions.execute(
            "SELECT COUNT(*) FROM user_attempts ua JOIN questions q ON ua.question_id = q.id "
            "WHERE ua.user_id = ? AND q.subject = ? AND ua.selected_option = q.correct_option_index",
            (session['user_id'], subject)
        ).fetchone()[0]
        accuracy = (subject_correct / subject_attempts * 100) if subject_attempts > 0 else 0.0
        subject_performance[subject] = accuracy

    # Toughness Breakdown
    toughness_levels = {
        'easy': "q.correct_percentage > 70",
        'medium': "q.correct_percentage BETWEEN 50 AND 70",
        'difficult': "q.correct_percentage < 50"
    }
    toughness_data = {}
    for level, condition in toughness_levels.items():
        level_attempts = conn_questions.execute(
            f"SELECT COUNT(*) FROM user_attempts ua JOIN questions q ON ua.question_id = q.id "
            f"WHERE ua.user_id = ? AND {condition}",
            (session['user_id'],)
        ).fetchone()[0]
        level_correct = conn_questions.execute(
            f"SELECT COUNT(*) FROM user_attempts ua JOIN questions q ON ua.question_id = q.id "
            f"WHERE ua.user_id = ? AND {condition} AND ua.selected_option = q.correct_option_index",
            (session['user_id'],)
        ).fetchone()[0]
        toughness_data[level] = {
            'attempts': level_attempts,
            'accuracy': (level_correct / level_attempts * 100) if level_attempts > 0 else 0.0
        }

    # Progress Over Time (last 30 days)
    progress_data = []
    today = datetime.now()
    for i in range(30):
        date = today - timedelta(days=i)
        date_str = date.strftime('%Y-%m-%d')
        day_attempts = conn_questions.execute(
            "SELECT COUNT(*) FROM user_attempts ua "
            "WHERE ua.user_id = ? AND DATE(ua.timestamp) = ?",
            (session['user_id'], date_str)
        ).fetchone()[0]
        day_correct = conn_questions.execute(
            "SELECT COUNT(*) FROM user_attempts ua JOIN questions q ON ua.question_id = q.id "
            "WHERE ua.user_id = ? AND DATE(ua.timestamp) = ? AND ua.selected_option = q.correct_option_index",
            (session['user_id'], date_str)
        ).fetchone()[0]
        day_accuracy = (day_correct / day_attempts * 100) if day_attempts > 0 else 0.0
        progress_data.append({'date': date.strftime('%d %b'), 'accuracy': day_accuracy})

    # Recent Activity (last 5 attempts)
    recent_attempts = conn_questions.execute(
        "SELECT ua.*, q.question_title, q.subject, q.chapter_name, q.correct_option_index "
        "FROM user_attempts ua JOIN questions q ON ua.question_id = q.id "
        "WHERE ua.user_id = ? ORDER BY ua.timestamp DESC LIMIT 5",
        (session['user_id'],)
    ).fetchall()

    conn_questions.close()

    return render_template('profile.html',
                          user=user_data,
                          progress_reports=progress_data,
                          attempted_questions=attempted_questions,
                          bookmarked_questions=bookmarked_questions,
                          total_attempts=total_attempts,
                          overall_accuracy=overall_accuracy,
                          subject_performance=subject_performance,
                          toughness_data=toughness_data,
                          progress_data=progress_data,
                          recent_attempts=recent_attempts)

# Edit Profile Route
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Please log in to edit your profile.', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        full_name = request.form['full_name']
        current_class = request.form['current_class']
        email = request.form['email']
        dob = request.form['dob']
        
        cursor.execute('''UPDATE users 
                        SET full_name = ?, current_class = ?, email = ?, dob = ?
                        WHERE id = ?''', (full_name, current_class, email, dob, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    cursor.execute('SELECT full_name, current_class, email, mobile_no, dob FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    
    user_data = {
        'full_name': user['full_name'],
        'current_class': user['current_class'],
        'email': user['email'],
        'mobile_no': user['mobile_no'],
        'dob': user['dob']
    }
    
    return render_template('edit_profile.html', user=user_data)

# Videos Route
@app.route('/videos')
def videos():
    return render_template('videos.html')

# Organic Chemistry Route
@app.route('/organic_chemistry')
def organic_chemistry():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all topics
    cursor.execute('SELECT * FROM video_topics WHERE subject = ?', ('Organic Chemistry',))
    topics = cursor.fetchall()
    
    # Fetch subtopics for each topic
    topics_with_subtopics = []
    for topic in topics:
        cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
        subtopics = cursor.fetchall()
        topic_dict = dict(topic)
        topic_dict['subtopics'] = subtopics
        topics_with_subtopics.append(topic_dict)
    
    # Get the selected topic from URL parameter
    selected_topic_id = request.args.get('topic')
    selected_topic = None
    selected_subtopic = None
    
    if selected_topic_id:
        cursor.execute('SELECT * FROM video_topics WHERE topic_id = ? AND subject = ?', (selected_topic_id, 'Organic Chemistry'))
        topic = cursor.fetchone()
        if topic:
            cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
            subtopics = cursor.fetchall()
            selected_topic = dict(topic)
            selected_topic['subtopics'] = subtopics
            
            # Get the selected subtopic from URL parameter
            selected_subtopic_id = request.args.get('subtopic')
            if selected_subtopic_id:
                for subtopic in subtopics:
                    if str(subtopic['id']) == selected_subtopic_id:
                        selected_subtopic = dict(subtopic)
                        break
    
    conn.close()
    
    return render_template('organic_chemistry.html', topics=topics_with_subtopics, selected_topic=selected_topic, selected_subtopic=selected_subtopic)

# Physical Chemistry Route
@app.route('/physical_chemistry')
def physical_chemistry():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all topics
    cursor.execute('SELECT * FROM video_topics WHERE subject = ?', ('Physical Chemistry',))
    topics = cursor.fetchall()
    
    # Fetch subtopics for each topic
    topics_with_subtopics = []
    for topic in topics:
        cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
        subtopics = cursor.fetchall()
        topic_dict = dict(topic)
        topic_dict['subtopics'] = subtopics
        topics_with_subtopics.append(topic_dict)
    
    # Get the selected topic from URL parameter
    selected_topic_id = request.args.get('topic')
    selected_topic = None
    selected_subtopic = None
    
    if selected_topic_id:
        cursor.execute('SELECT * FROM video_topics WHERE topic_id = ? AND subject = ?', (selected_topic_id, 'Physical Chemistry'))
        topic = cursor.fetchone()
        if topic:
            cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
            subtopics = cursor.fetchall()
            selected_topic = dict(topic)
            selected_topic['subtopics'] = subtopics
            
            # Get the selected subtopic from URL parameter
            selected_subtopic_id = request.args.get('subtopic')
            if selected_subtopic_id:
                for subtopic in subtopics:
                    if str(subtopic['id']) == selected_subtopic_id:
                        selected_subtopic = dict(subtopic)
                        break
    
    conn.close()
    
    return render_template('physical_chemistry.html', topics=topics_with_subtopics, selected_topic=selected_topic, selected_subtopic=selected_subtopic)

# Inorganic Chemistry Route
@app.route('/inorganic_chemistry')
def inorganic_chemistry():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all topics
    cursor.execute('SELECT * FROM video_topics WHERE subject = ?', ('Inorganic Chemistry',))
    topics = cursor.fetchall()
    
    # Fetch subtopics for each topic
    topics_with_subtopics = []
    for topic in topics:
        cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
        subtopics = cursor.fetchall()
        topic_dict = dict(topic)
        topic_dict['subtopics'] = subtopics
        topics_with_subtopics.append(topic_dict)
    
    # Get the selected topic from URL parameter
    selected_topic_id = request.args.get('topic')
    selected_topic = None
    selected_subtopic = None
    
    if selected_topic_id:
        cursor.execute('SELECT * FROM video_topics WHERE topic_id = ? AND subject = ?', (selected_topic_id, 'Inorganic Chemistry'))
        topic = cursor.fetchone()
        if topic:
            cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
            subtopics = cursor.fetchall()
            selected_topic = dict(topic)
            selected_topic['subtopics'] = subtopics
            
            # Get the selected subtopic from URL parameter
            selected_subtopic_id = request.args.get('subtopic')
            if selected_subtopic_id:
                for subtopic in subtopics:
                    if str(subtopic['id']) == selected_subtopic_id:
                        selected_subtopic = dict(subtopic)
                        break
    
    conn.close()
    
    return render_template('inorganic_chemistry.html', topics=topics_with_subtopics, selected_topic=selected_topic, selected_subtopic=selected_subtopic)

# Physics Route
@app.route('/physics')
def physics():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all topics
    cursor.execute('SELECT * FROM video_topics WHERE subject = ?', ('Physics',))
    topics = cursor.fetchall()
    
    # Fetch subtopics for each topic
    topics_with_subtopics = []
    for topic in topics:
        cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
        subtopics = cursor.fetchall()
        topic_dict = dict(topic)
        topic_dict['subtopics'] = subtopics
        topics_with_subtopics.append(topic_dict)
    
    # Get the selected topic from URL parameter
    selected_topic_id = request.args.get('topic')
    selected_topic = None
    selected_subtopic = None
    
    if selected_topic_id:
        cursor.execute('SELECT * FROM video_topics WHERE topic_id = ? AND subject = ?', (selected_topic_id, 'Physics'))
        topic = cursor.fetchone()
        if topic:
            cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
            subtopics = cursor.fetchall()
            selected_topic = dict(topic)
            selected_topic['subtopics'] = subtopics
            
            # Get the selected subtopic from URL parameter
            selected_subtopic_id = request.args.get('subtopic')
            if selected_subtopic_id:
                for subtopic in subtopics:
                    if str(subtopic['id']) == selected_subtopic_id:
                        selected_subtopic = dict(subtopic)
                        break
    
    conn.close()
    
    return render_template('physics.html', topics=topics_with_subtopics, selected_topic=selected_topic, selected_subtopic=selected_subtopic)

# Math Route
@app.route('/math')
def math():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all topics
    cursor.execute('SELECT * FROM video_topics WHERE subject = ?', ('Mathematics',))
    topics = cursor.fetchall()
    
    # Fetch subtopics for each topic
    topics_with_subtopics = []
    for topic in topics:
        cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
        subtopics = cursor.fetchall()
        topic_dict = dict(topic)
        topic_dict['subtopics'] = subtopics
        topics_with_subtopics.append(topic_dict)
    
    # Get the selected topic from URL parameter
    selected_topic_id = request.args.get('topic')
    selected_topic = None
    selected_subtopic = None
    
    if selected_topic_id:
        cursor.execute('SELECT * FROM video_topics WHERE topic_id = ? AND subject = ?', (selected_topic_id, 'Mathematics'))
        topic = cursor.fetchone()
        if topic:
            cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
            subtopics = cursor.fetchall()
            selected_topic = dict(topic)
            selected_topic['subtopics'] = subtopics
            
            # Get the selected subtopic from URL parameter
            selected_subtopic_id = request.args.get('subtopic')
            if selected_subtopic_id:
                for subtopic in subtopics:
                    if str(subtopic['id']) == selected_subtopic_id:
                        selected_subtopic = dict(subtopic)
                        break
    
    conn.close()
    
    return render_template('math.html', topics=topics_with_subtopics, selected_topic=selected_topic, selected_subtopic=selected_subtopic)

# Botany Route
@app.route('/botany')
def botany():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all topics
    cursor.execute('SELECT * FROM video_topics WHERE subject = ?', ('Botany',))
    topics = cursor.fetchall()
    
    # Fetch subtopics for each topic
    topics_with_subtopics = []
    for topic in topics:
        cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
        subtopics = cursor.fetchall()
        topic_dict = dict(topic)
        topic_dict['subtopics'] = subtopics
        topics_with_subtopics.append(topic_dict)
    
    # Get the selected topic from URL parameter
    selected_topic_id = request.args.get('topic')
    selected_topic = None
    selected_subtopic = None
    
    if selected_topic_id:
        cursor.execute('SELECT * FROM video_topics WHERE topic_id = ? AND subject = ?', (selected_topic_id, 'Botany'))
        topic = cursor.fetchone()
        if topic:
            cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
            subtopics = cursor.fetchall()
            selected_topic = dict(topic)
            selected_topic['subtopics'] = subtopics
            
            # Get the selected subtopic from URL parameter
            selected_subtopic_id = request.args.get('subtopic')
            if selected_subtopic_id:
                for subtopic in subtopics:
                    if str(subtopic['id']) == selected_subtopic_id:
                        selected_subtopic = dict(subtopic)
                        break
    
    conn.close()
    
    return render_template('botany.html', topics=topics_with_subtopics, selected_topic=selected_topic, selected_subtopic=selected_subtopic)

# Zoology Route
@app.route('/zoology')
def zoology():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all topics
    cursor.execute('SELECT * FROM video_topics WHERE subject = ?', ('Zoology',))
    topics = cursor.fetchall()
    
    # Fetch subtopics for each topic
    topics_with_subtopics = []
    for topic in topics:
        cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
        subtopics = cursor.fetchall()
        topic_dict = dict(topic)
        topic_dict['subtopics'] = subtopics
        topics_with_subtopics.append(topic_dict)
    
    # Get the selected topic from URL parameter
    selected_topic_id = request.args.get('topic')
    selected_topic = None
    selected_subtopic = None
    
    if selected_topic_id:
        cursor.execute('SELECT * FROM video_topics WHERE topic_id = ? AND subject = ?', (selected_topic_id, 'Zoology'))
        topic = cursor.fetchone()
        if topic:
            cursor.execute('SELECT * FROM subtopics WHERE video_topic_id = ?', (topic['id'],))
            subtopics = cursor.fetchall()
            selected_topic = dict(topic)
            selected_topic['subtopics'] = subtopics
            
            # Get the selected subtopic from URL parameter
            selected_subtopic_id = request.args.get('subtopic')
            if selected_subtopic_id:
                for subtopic in subtopics:
                    if str(subtopic['id']) == selected_subtopic_id:
                        selected_subtopic = dict(subtopic)
                        break
    
    conn.close()
    
    return render_template('zoology.html', topics=topics_with_subtopics, selected_topic=selected_topic, selected_subtopic=selected_subtopic)

# Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        mobile_no = request.form['mobile_no']
        message = request.form['message']
        
        conn = sqlite3.connect('contacts.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO contacts (name, email, mobile_no, message) VALUES (?, ?, ?, ?)',
                      (name, email, mobile_no, message))
        conn.commit()
        conn.close()
        
        flash('Your message has been sent!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

# List of JSON files for each subject with corresponding subject names
json_files = [
    ('data/chemistry_questions_mathjax.json', 'Chemistry'),
    ('data/physics_questions_mathjax.json', 'Physics'),
    ('data/botany_questions_mathjax.json', 'Botany'),
    ('data/zoology_questions_mathjax.json', 'Zoology')
]

# Initialize SQLite database for csksir.db
def init_db():
    conn = sqlite3.connect('csksir.db')
    c = conn.cursor()

    # Create questions table with a subject column
    c.execute('''CREATE TABLE IF NOT EXISTS questions (
        id TEXT PRIMARY KEY,
        question_num INTEGER,
        question_title TEXT,
        options TEXT,
        correct_option_index INTEGER,
        explanation TEXT,
        ncert BOOLEAN,
        year TEXT,
        exam TEXT,
        chapter_name TEXT,
        subtopic_name TEXT,
        subject TEXT,
        correct_percentage FLOAT,
        option1_percentage FLOAT,
        option2_percentage FLOAT,
        option3_percentage FLOAT,
        option4_percentage FLOAT
    )''')

    # Create user_attempts table with timestamp
    c.execute('''CREATE TABLE IF NOT EXISTS user_attempts (
        user_id INTEGER,
        question_id TEXT,
        selected_option INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, question_id)
    )''')

    # Create bookmarks table
    c.execute('''CREATE TABLE IF NOT EXISTS bookmarks (
        user_id INTEGER,
        question_id TEXT,
        PRIMARY KEY (user_id, question_id)
    )''')

    # Check if the questions table is empty
    c.execute("SELECT COUNT(*) FROM questions")
    if c.fetchone()[0] == 0:
        # Load questions from each JSON file
        for json_file, subject in json_files:
            if os.path.exists(json_file):
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        questions_data = json.load(f)
                        question_count = 0
                        for q in questions_data:
                            # Handle None values for percentage fields
                            correct_percentage = float(q['analytics_correctPercentage']) if q['analytics_correctPercentage'] is not None else 0.0
                            option1_percentage = float(q['analytics_option1Percentage']) if q['analytics_option1Percentage'] is not None else 0.0
                            option2_percentage = float(q['analytics_option2Percentage']) if q['analytics_option2Percentage'] is not None else 0.0
                            option3_percentage = float(q['analytics_option3Percentage']) if q['analytics_option3Percentage'] is not None else 0.0
                            option4_percentage = float(q['analytics_option4Percentage']) if q['analytics_option4Percentage'] is not None else 0.0

                            c.execute('''INSERT INTO questions (
                                id, question_num, question_title, options, correct_option_index, explanation,
                                ncert, year, exam, chapter_name, subtopic_name, subject,
                                correct_percentage, option1_percentage, option2_percentage, option3_percentage, option4_percentage
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                                q['id'], q['questionNum'], q['questionTitle'], q['options'], q['correctOptionIndex'],
                                q['explanation'], q['ncert'], q['year'], q['exam'], q['chapter_name_full'],
                                q['subtopic_names'], subject,
                                correct_percentage,
                                option1_percentage, option2_percentage,
                                option3_percentage, option4_percentage
                            ))
                            question_count += 1
                        print(f"Loaded {question_count} questions from {json_file} for subject {subject}")
                except Exception as e:
                    print(f"Error loading {json_file}: {e}")
                    continue
            else:
                print(f"Warning: {json_file} not found.")

    conn.commit()
    conn.close()

# Call init_db() when the app starts
with app.app_context():
    init_db()

# Route to fetch chapters for a selected subject
@app.route('/get_chapters', methods=['GET'])
def get_chapters():
    subject = request.args.get('subject', '')
    question_type = request.args.get('question_type', '')
    conn = get_db()
    query = "SELECT DISTINCT chapter_name FROM questions"
    params = []
    if question_type == 'pyq':
        query += " WHERE exam = 'NEET'"
    elif question_type == 'ncert':
        query += " WHERE ncert = 1"
    else:
        query += " WHERE 1=1"
    
    if subject:
        query += " AND subject = ?"
        params.append(subject)
    chapters = conn.execute(query, params).fetchall()
    chapters = [row['chapter_name'] for row in chapters]
    print(f"Fetched chapters for subject {subject}, question_type {question_type}: {chapters}")
    conn.close()
    return jsonify(chapters)

# PYQ Route
@app.route('/pyq', methods=['GET'])
def pyq():
    print("Session is_admin:", session.get('is_admin'))  # Debug print
    # Get filter parameters
    subject = request.args.get('subject', '')
    chapter = request.args.get('chapter', '')
    question_type = request.args.get('question_type', '')
    toughness = request.args.get('toughness', '')
    search = request.args.get('search', '')
    subtopics = request.args.getlist('subtopics')  # Allow multiple subtopics
    page = int(request.args.get('page', 1))
    questions_per_page = 10

    # Connect to the database
    conn = get_db()
    conn.row_factory = sqlite3.Row

    # Build query for counting total questions
    count_query = "SELECT COUNT(*) FROM questions"
    count_params = []
    if question_type == 'pyq':
        count_query += " WHERE exam = 'NEET'"
    elif question_type == 'ncert':
        count_query += " WHERE ncert = 1"
    else:
        count_query += " WHERE 1=1"

    if subject:
        count_query += " AND subject = ?"
        count_params.append(subject)
    if chapter:
        count_query += " AND chapter_name = ?"
        count_params.append(chapter)
    if subtopics:
        count_query += " AND subtopic_name IN ({})".format(','.join(['?'] * len(subtopics)))
        count_params.extend(subtopics)
    if toughness:
        if toughness == 'easy':
            count_query += " AND correct_percentage > 70"
        elif toughness == 'medium':
            count_query += " AND correct_percentage BETWEEN 50 AND 70"
        elif toughness == 'difficult':
            count_query += " AND correct_percentage < 50"
    if search:
        count_query += " AND (chapter_name LIKE ? OR question_title LIKE ?)"
        count_params.extend([f"%{search}%", f"%{search}%"])

    # Build query for fetching questions
    query = "SELECT * FROM questions"
    params = []
    if question_type == 'pyq':
        query += " WHERE exam = 'NEET'"
    elif question_type == 'ncert':
        query += " WHERE ncert = 1"
    else:
        query += " WHERE 1=1"

    if subject:
        query += " AND subject = ?"
        params.append(subject)
    if chapter:
        query += " AND chapter_name = ?"
        params.append(chapter)
    if subtopics:
        query += " AND subtopic_name IN ({})".format(','.join(['?'] * len(subtopics)))
        params.extend(subtopics)
    if toughness:
        if toughness == 'easy':
            query += " AND correct_percentage > 70"
        elif toughness == 'medium':
            query += " AND correct_percentage BETWEEN 50 AND 70"
        elif toughness == 'difficult':
            query += " AND correct_percentage < 50"
    if search:
        query += " AND (chapter_name LIKE ? OR question_title LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    # Pagination
    offset = (page - 1) * questions_per_page
    query += f" ORDER BY question_num ASC LIMIT {questions_per_page} OFFSET ?"
    params.append(offset)

    # Fetch questions
    questions_raw = conn.execute(query, params).fetchall()

    # Process questions to clean options
    questions = []
    for q in questions_raw:
        q_dict = dict(q)
        options = json.loads(q_dict['options'])
        q_dict['options'] = [opt.strip('()') for opt in options]
        questions.append(q_dict)

    # Calculate total pages
    total_questions = conn.execute(count_query, count_params).fetchone()[0]
    total_pages = (total_questions + questions_per_page - 1) // questions_per_page

    # Calculate the starting question number for the current page
    start_number = (page - 1) * questions_per_page + 1

    # Fetch chapters for the selected subject
    chapters_query = "SELECT DISTINCT chapter_name FROM questions"
    chapters_params = []
    if question_type == 'pyq':
        chapters_query += " WHERE exam = 'NEET'"
    elif question_type == 'ncert':
        chapters_query += " WHERE ncert = 1"
    else:
        chapters_query += " WHERE 1=1"
    
    if subject:
        chapters_query += " AND subject = ?"
        chapters_params.append(subject)
    chapters = conn.execute(chapters_query, chapters_params).fetchall()
    chapters = [row['chapter_name'] for row in chapters]

    # Fetch subtopics for the selected chapter
    subtopics_query = "SELECT DISTINCT subtopic_name FROM questions"
    subtopics_params = []
    if question_type == 'pyq':
        subtopics_query += " WHERE exam = 'NEET'"
    elif question_type == 'ncert':
        subtopics_query += " WHERE ncert = 1"
    else:
        subtopics_query += " WHERE 1=1"
    
    if subject:
        subtopics_query += " AND subject = ?"
        subtopics_params.append(subject)
    if chapter:
        subtopics_query += " AND chapter_name = ?"
        subtopics_params.append(chapter)
    subtopics_rows = conn.execute(subtopics_query, subtopics_params).fetchall()
    available_subtopics = [row['subtopic_name'] for row in subtopics_rows if row['subtopic_name']]

    # Fetch bookmarked questions for the current user
    bookmarked_questions = []
    if 'user_id' in session:
        bookmarked_questions = conn.execute(
            "SELECT question_id FROM bookmarks WHERE user_id = ?",
            (session['user_id'],)
        ).fetchall()
        bookmarked_questions = [row['question_id'] for row in bookmarked_questions]

    # Fetch attempted questions for the current user
    attempted_questions = []
    if 'user_id' in session:
        attempted_questions = conn.execute(
            "SELECT question_id FROM user_attempts WHERE user_id = ?",
            (session['user_id'],)
        ).fetchall()
        attempted_questions = [row['question_id'] for row in attempted_questions]

    conn.close()

    return render_template('pyq.html',
        questions=questions,
        subject=subject,
        selected_chapter=chapter,
        question_type=question_type,
        toughness=toughness,
        search=search,
        chapters=chapters,
        available_subtopics=available_subtopics,
        selected_subtopics=subtopics,
        page=page,
        total_pages=total_pages,
        start_number=start_number,
        bookmarked_questions=bookmarked_questions,
        attempted_questions=attempted_questions
    )
# subtopics route

@app.route('/get_subtopics', methods=['GET'])
def get_subtopics():
    subject = request.args.get('subject', '')
    chapter = request.args.get('chapter', '')
    question_type = request.args.get('question_type', '')

    # Connect to the database
    conn = get_db()
    conn.row_factory = sqlite3.Row

    # Build query for fetching subtopics
    query = "SELECT DISTINCT subtopic_name FROM questions"
    params = []
    if question_type == 'pyq':
        query += " WHERE exam = 'NEET'"
    elif question_type == 'ncert':
        query += " WHERE ncert = 1"
    else:
        query += " WHERE 1=1"
    
    if subject:
        query += " AND subject = ?"
        params.append(subject)
    if chapter:
        query += " AND chapter_name = ?"
        params.append(chapter)

    subtopics_rows = conn.execute(query, params).fetchall()
    subtopics = [row['subtopic_name'] for row in subtopics_rows if row['subtopic_name']]

    conn.close()
    return jsonify(subtopics)


# Route to submit an answer
@app.route('/submit_answer', methods=['POST'])
def submit_answer():
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    data = request.get_json()
    question_id = data.get('question_id')
    selected_option = data.get('selected_option')
    user_id = session['user_id']

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO user_attempts (user_id, question_id, selected_option) VALUES (?, ?, ?)",
        (user_id, question_id, selected_option)
    )
    conn.commit()
    conn.close()

    return jsonify({'status': 'success'})

# Route to toggle bookmark
@app.route('/toggle_bookmark', methods=['POST'])
def toggle_bookmark():
    if 'user_id' not in session:
        return jsonify({'error': 'User not logged in'}), 401

    data = request.get_json()
    question_id = data.get('question_id')
    user_id = session['user_id']

    conn = get_db()
    existing = conn.execute(
        "SELECT * FROM bookmarks WHERE user_id = ? AND question_id = ?",
        (user_id, question_id)
    ).fetchone()

    if existing:
        conn.execute(
            "DELETE FROM bookmarks WHERE user_id = ? AND question_id = ?",
            (user_id, question_id)
        )
        bookmarked = False
    else:
        conn.execute(
            "INSERT INTO bookmarks (user_id, question_id) VALUES (?, ?)",
            (user_id, question_id)
        )
        bookmarked = True

    conn.commit()
    conn.close()

    return jsonify({'bookmarked': bookmarked})

# edit questions 

@app.route('/edit_question', methods=['POST'])
def edit_question():
    if not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Unauthorized access'}), 403

    try:
        data = request.get_json()
        print("Received data for edit_question:", data)  # Debug: Log the incoming data
        question_id = data['question_id']
        question_title = data['question_title']
        options = data['options']  # List of 4 options
        correct_option_index = data['correct_option_index']
        explanation = data['explanation'] or None
        subtopic_name = data['subtopic_name'] or None
        exam = data['exam'] or None
        year = data['year'] or None
        ncert = data['ncert']

        # Validate inputs
        if not question_title or not all(options) or correct_option_index not in range(4):
            return jsonify({'success': False, 'error': 'Invalid input data'}), 400

        # Convert options list to JSON string
        options_json = json.dumps(options)

        # Update the database
        conn = sqlite3.connect('csksir.db')
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE questions
            SET question_title = ?, options = ?, correct_option_index = ?, explanation = ?,
                subtopic_name = ?, exam = ?, year = ?, ncert = ?
            WHERE id = ?
        ''', (question_title, options_json, correct_option_index, explanation,
              subtopic_name, exam, year, ncert, question_id))
        conn.commit()
        conn.close()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    
#Delete question  
@app.route('/delete_question', methods=['POST'])
def delete_question():
    if not session.get('is_admin'):
        return jsonify({'success': False, 'error': 'Unauthorized access'}), 403
    try:
        data = request.get_json()
        question_id = data['question_id']

        # Delete the question from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM questions WHERE id = ?', (question_id,))
        conn.commit()
        conn.close()
        print("Question updated successfully for ID:", question_id)  # Debug: Confirm update
        return jsonify({'success': True})
    except Exception as e:
        print("Error in edit_question:", str(e))  # Debug: Log any errors
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)