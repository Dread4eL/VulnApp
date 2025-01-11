from flask import render_template, request, redirect
from app import app 
import mysql.connector
import logging
import logstash
import socket
import json

# Custom JSON Formatter
class CustomLogstashFormatter(logging.Formatter):
    def format(self, record):
        log = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'funcName': record.funcName,
            'lineno': record.lineno,
            'app_name': 'webapp',  # Add context like app name
        }
        return json.dumps(log)
        
      
# Logstash configuration
LOGSTASH_HOST = 'localhost'  # Change if Logstash is on another machine
LOGSTASH_PORT = 5044         # Default Logstash port for Beats input
# Database Configuration
db_config = {
    'user': 'NewUser',        # Your MySQL username
    'password': 'pouet',        # Your MySQL password
    'host': 'localhost',
    'database': 'testDBusers'   # Your database name
}

logger = logging.getLogger('vulnapp_logger')
logger.setLevel(logging.DEBUG)

# Add a SocketHandler for Logstash
logger.addHandler(logstash.LogstashHandler('localhost', 5959,version=1))
#logstash_handler = logging.handlers.SocketHandler(LOGSTASH_HOST, LOGSTASH_PORT)
#logstash_handler.setFormatter(CustomLogstashFormatter())
#logger.addHandler(logstash_handler)
#logger.setLevel(logging.INFO)
#handler = logging.FileHandler('/home/ubuntu/VulnApp/infos_alerts.log') # Spécifiez le chemin du fichier
#formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#handler.setFormatter(formatter)
#logger.addHandler(handler)

# Route for handling the landing page
@app.route('/')
def index():
    return render_template('index.html')

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        
        print("new User")
        logger.info('New user signup: %s, %s, %s, %s, %s ',firstName, lastName, email, username, password)

        # Hash the password for security
        #hashed_password = generate_password_hash(password, method='sha256')

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (firstName, lastName, email, username, password) VALUES (%s,%s, %s, %s, %s)", (firstName, lastName, email, username, password))
        conn.commit()

        cursor.close()
        conn.close()

        return render_template('login.html')

    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=''
   
    print(request.form)
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        logger.info('User login attempt: %s', username)

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        query ="SELECT * FROM users WHERE username= '"+username+"' AND password= '"+password+"' ;"
        print(query)
        cursor.execute(query)
        user = cursor.fetchall()
        print(user)
        cursor.close()
        conn.close()

        if user and user[0]['isModerator']==1:
            # User is authenticated
            logger.info('Successful admin login attempt with the username: %s', username)
            return redirect('/admin')
        elif user:
            logger.info('Successful login attempt with the username: %s', username)
            return redirect('/user')
        else:
            # Invalid credentials
            print("Invalid Credentials")
            logger.info('Failed login attempt with the username: %s', username)
            return render_template('login.html',msg='Login Failed, Invalid Credentials !!')

    return render_template('login.html',msg=msg)


@app.route('/login_safe', methods=['GET', 'POST'])
def login_safe():
    msg =''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        List_sqli = ["'",'"','%','-']
        for let in username:
            if let in List_sqli:
            	logger.warning('An attempt for SQL injection has been made with %s', username)
                return render_template('login_safe.html',msg = 'I do not want SQLi !!, wrong characters')
        for let in password:
            if let in List_sqli:
            	logger.warning('An attempt for SQL injection has been made with %s', username)
                return render_template('login_safe.html',msg = 'I do not want SQLi !!, wrong characters')

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE username= %s AND password=%s"
        cursor.execute(query, (username, password))
        user = cursor.fetchall()
        print(user)
        cursor.close()
        conn.close()

        if user and user[0]['isModerator']==1:
            # User is authenticated
            logger.info('Successful admin login attempt with the username: %s', username)
            return redirect('/admin')
        elif user:
            logger.info('Successful login attempt with the username: %s', username)
            return redirect('/user')
        else:
            # Invalid credentials
            print("Invalid Credentials")
            logger.info('Failed login attempt with the username: %s', username)
            return render_template('login.html',msg='Login Failed, Invalid Credentials !!')

    return render_template('login_safe.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    users = []
    print(request.form)
    if request.method == 'POST':
        username_search = request.form['username']

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM users WHERE username LIKE '%"+username_search+"%';"
        print(query)

        cursor.execute(query)

        users = cursor.fetchall()

        cursor.close()
        conn.close()


    return render_template('search.html', users=users)

@app.route('/user')
def user_page():
    # This page can be accessed by standard users
    return render_template('user.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():

    return render_template('admin.html')


@app.route('/admin/add', methods=['POST'])
def admin_add():
    msg_add = ''
    msg_del = ''
    msg = ''
    print(request.form)
    if request.method == 'POST':
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']

        # Hash the password for security
        #hashed_password = generate_password_hash(password, method='sha256')

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        cursor.execute("INSERT INTO users (firstName, lastName, email, username, password) VALUES (%s,%s, %s, %s, %s)", (firstName, lastName, email, username, password))
        conn.commit()

        cursor.close()
        conn.close()
        msg = 'User added successfully!'
        return render_template('admin.html', msg_add=msg)

@app.route('/admin/del', methods=['POST'])
def admin_del():
    msg_add = ''
    msg_del = ''
    msg = ''
    if request.method == 'POST':
        # Logic for deleting a user
        user_id = request.form['user_id']
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        msg = 'User deleted successfully!'
        return render_template('admin.html', msg_del=msg)

@app.route('/admin/search', methods=['POST'])
def admin_search():
    msg_add = ''
    msg_del = ''
    msg = ''
    users=[]
    print(request.form)
    if request.method == 'POST':
        username_search = request.form['username']
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE username LIKE '%"+username_search+"%';"
        cursor.execute(query,multi=True)
        users = cursor.fetchall()
        cursor.close()
        conn.close()

        return render_template('admin.html', users=users, msg=msg)

@app.route('/sqli')
def sqli_page():
    return render_template('sqli.html') 

@app.route('/xss')
def xss_page():
    return render_template('xss.html')

# ... (Add more routes for other vulnerabilities)
