import sqlite3
import os

def migrate():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'cybershield.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT citizen_id FROM cases LIMIT 1')
        print('citizen_id already exists in cases.')
    except sqlite3.OperationalError:
        print('Adding citizen_id to cases...')
        cursor.execute('ALTER TABLE cases ADD COLUMN citizen_id INTEGER DEFAULT NULL')
        conn.commit()

    # Populate citizen_id based on submitted_by
    print('Populating citizen_id from submitted_by...')
    cursor.execute('SELECT id, username FROM users')
    users = cursor.fetchall()
    
    for uid, username in users:
        cursor.execute('UPDATE cases SET citizen_id = ? WHERE submitted_by = ?', (uid, username))
    
    conn.commit()
    conn.close()
    print('Migration complete.')

if __name__ == '__main__':
    migrate()
