# -*- coding: utf-8 -*-
import requests
from bs4 import BeautifulSoup
import sqlite3
import time
from urllib.parse import urljoin

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
}

base_url = 'https://questions.examside.com'

def scrape_exam(exam_url, exam_name):
    pyqs = []
    try:
        response = requests.get(exam_url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        links = soup.select('a[href*="/past-years/"], a[href*="/question-paper-"]')
        for link in links[:10]:
            question_url = urljoin(base_url, link['href'])
            title = link.text.strip()

            subject = 'Unknown'
            year = '2023'
            if 'Physics' in title or 'physics' in question_url:
                subject = 'Physics'
            elif 'Chemistry' in title or 'chemistry' in question_url:
                subject = 'Chemistry'
            elif 'Biology' in title or 'biology' in question_url:
                subject = 'Biology'
            elif 'Math' in title or 'math' in question_url:
                subject = 'Math'
            for y in range(1978, 2026):  # Wide range for JEE Advanced (1978-2025)
                if str(y) in title or str(y) in question_url:
                    year = str(y)

            time.sleep(1)
            try:
                response = requests.get(question_url, headers=headers)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')

                question_text = f"Question from {exam_name} {subject} {year}: Refer to web/PDF for full content."
                question_div = soup.select_one('div.question-content, div.question, p, div.content')
                if question_div:
                    question_text = question_div.text.strip()[:200] or question_text

                solution_text = f"Solution for {exam_name} {subject} {year}: Available on ExamSIDE."
                solution_div = soup.select_one('div.solution-content, div.answer, div.solution, div.explanation')
                if solution_div:
                    solution_text = solution_div.text.strip()[:200] or solution_text

                pdf_link = question_url
                pdf_anchor = soup.select_one('a[href*=".pdf"]')
                if pdf_anchor:
                    pdf_link = urljoin(base_url, pdf_anchor['href'])

                pyqs.append({
                    'exam': exam_name,
                    'subject': subject,
                    'year': int(year),
                    'question_text': question_text,
                    'solution_text': solution_text,
                    'pdf_link': pdf_link
                })
                print(f"Scraped: {exam_name} {subject} {year} from {question_url}")
            except Exception as e:
                print(f"Error scraping question {question_url}: {e}")
    except Exception as e:
        print(f"Error scraping exam {exam_url}: {e}")
    return pyqs

def store_pyqs(pyqs):
    try:
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
            cursor.execute('DELETE FROM questions')
            for pyq in pyqs:
                cursor.execute('''
                    INSERT INTO questions (exam, subject, year, question_text, solution_text, pdf_link)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (pyq['exam'], pyq['subject'], pyq['year'], pyq['question_text'], pyq['solution_text'], pyq['pdf_link']))
            conn.commit()
            print(f"Stored {len(pyqs)} PYQs in pyqs.db")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def main():
    exams = [
        ('https://questions.examside.com/past-years/jee/jee-main', 'JEE Main'),
        ('https://questions.examside.com/past-years/jee/jee-advanced', 'JEE Advanced'),
        ('https://questions.examside.com/past-years/medical/neet', 'NEET')
    ]

    all_pyqs = []
    for exam_url, exam_name in exams:
        print(f"Scraping {exam_name}...")
        pyqs = scrape_exam(exam_url, exam_name)
        all_pyqs.extend(pyqs)
        time.sleep(2)

    if all_pyqs:
        store_pyqs(all_pyqs)
    else:
        print("No PYQs scraped.")

if __name__ == '__main__':
    main()