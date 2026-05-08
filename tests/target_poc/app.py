from flask import Flask, request
import sqlite3

# Mock decorator per Semgrep
def login_required(f):
    return f

app = Flask(__name__)

@app.route('/users', methods=['GET'])
@login_required
def get_users():
    return "Users list"

@app.route('/users/add', methods=['POST'])
def add_user():
    return "User added", 201

@app.route('/users/<int:id>', methods=['GET'])
def get_user_by_id(id):
    # Vulnerabilità SQL Injection intenzionale per Semgrep (A03:2021)
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + str(request.args.get('query_id'))
    cursor.execute(query)
    
    # Vulnerabilità RCE intenzionale
    eval(request.args.get('cmd'))
    
    return "User data"

# Shadow API non presente in openapi.yaml
@app.route('/admin/secret', methods=['GET'])
def secret_admin():
    return "Super secret admin area"

if __name__ == '__main__':
    app.run(debug=True)
