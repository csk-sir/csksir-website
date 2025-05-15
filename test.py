import sqlite3
conn = sqlite3.connect('C:\\csksir-website\\pyqs.db')
cursor = conn.cursor()
cursor.execute('SELECT exam, subject, year, question_text, pdf_link FROM questions')
print(cursor.fetchall())
conn.close()