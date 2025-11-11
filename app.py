import json, sqlite3, secrets, click, functools, os, hashlib,time, random, sys, bcrypt, string
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)

def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()

    alphabet = string.ascii_letters + string.digits + string.punctuation
    admin_pw = ''.join(secrets.choice(alphabet) for _ in range(16))  # 16-char random password

    admin_pw_hash = bcrypt.hashpw(admin_pw.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db.executescript("""

DROP TABLE IF EXISTS users; 
DROP TABLE IF EXISTS notes;

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assocUser INTEGER NOT NULL,
    dateWritten DATETIME NOT NULL,
    note TEXT NOT NULL,
    publicID INTEGER NOT NULL,
    publicNote BOOLEAN DEFAULT 0
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

""")
    
    statement = """INSERT INTO users(id,username,password) VALUES(null,?,?);"""
    print("Admin Password (save this!): %s" %admin_pw)
    db.execute(statement, ("admin",admin_pw_hash))
    conn.commit()
    conn.close()


### APPLICATION SETUP ###
app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app = app,
    storage_uri="memory://"
)
app.database = "db.sqlite3"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JS access
    SESSION_COOKIE_SECURE=False,    # Only over HTTPS
    SESSION_COOKIE_SAMESITE='Lax'  # Prevent CSRF
)
app.secret_key = os.urandom(32)

@app.before_request
def generate_nonce():
    g.nonce = secrets.token_urlsafe(16)

csrf = CSRFProtect(app)

### Globally setting CSP headers
@app.after_request
def set_csp_headers(response):
    response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' https://cdn.jsdelivr.net; 'nonce-{g.nonce}';"
            f"style-src 'self' https://fonts.googleapis.com 'nonce-{g.nonce}'; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:;"
            "form-action 'self'; "
            "frame-ancestors 'none';"
    )

    response.headers["X-Content-Type-Options"] = "nosniff" #x-content-type-options header 

    # Fix Version Info vulnerability (doesn't work)
    response.headers.pop('Server', None)
    return response

### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))


@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror=""
    #Posting a new note:
    if request.method == 'POST' and request.form['submit_button'] == 'add note':
            note = request.form['noteinput']
            try :
                request.form['publicnote']
                publicNote = True
            except:
                publicNote = False
            db = connect_db()
            c = db.cursor()
            statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID,publicNote) VALUES(null,?,?,?,?,?);"""
            print(statement)
            c.execute(statement, (session['userid'],time.strftime('%Y-%m-%d %H:%M:%S'),note,random.randrange(1000000000, 9999999999),publicNote))
            db.commit()
            db.close()
            return redirect(url_for('notes'))
    
    db = connect_db()
    c = db.cursor()
    statement = "SELECT * FROM notes WHERE assocUser = ?;"
    print(statement)
    c.execute(statement, (session['userid'],))
    notes = c.fetchall()
    db.close()
    
    return render_template('notes.html',notes=notes,importerror=importerror)

@app.route("/notes/import/", methods=['POST'])
@login_required
@limiter.limit(limit_value="20 per minute", error_message="Too many imports, try again in a minute")
def import_note():
    importerror = ""
    noteid = request.form['noteid']

    db = connect_db()
    c = db.cursor()
    statement = """SELECT * FROM notes WHERE publicID = ? AND publicNote = 1;"""
    c.execute(statement, (noteid,))
    result = c.fetchall()

    if len(result) > 0:
        row = result[0]
        insert_stmt = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID, publicNote)
                         VALUES(null,?,?,?,?);"""
        c.execute(insert_stmt, (session['userid'], row[2], row[3], row[4]))
        db.commit()
        db.close()
        return redirect(url_for('notes'))
    else:
        db.close()
        importerror = "No such note with that ID!"
        return render_template('notes.html', importerror=importerror)
    
@app.route("/notes/delete/<int:note_id>", methods=['POST'])
@login_required
def delete_note(note_id):
    user_id = session['userid']

    db = connect_db()
    c = db.cursor()
    statement = "DELETE FROM notes WHERE id = ? AND assocUser = ?"
    c.execute(statement, (note_id, user_id))
    db.commit()
    db.close()

    return(redirect(url_for('notes')))

@app.route("/login/", methods=('GET', 'POST'))
@limiter.limit(limit_value="15 per 5 minutes", error_message="Too many login attempts, please try again in 5 minutes.")
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if (username == "" or password == ""):
            error = "Please provide both username and password!"
            return render_template('login.html',error=error)
        elif (len(username)>32 or len(password)>32):
            error = "Username and password must be less than 32 characters!"
            return render_template('login.html',error=error)
        
        db = connect_db()
        c = db.cursor()
        """ Legacy vulnerable code:
        statement = "SELECT * FROM users WHERE username = '%s' AND password = '%s';" %(username, password)
        c.execute(statement) 
        """
        statement = "SELECT * FROM users WHERE username = ?;"
        args = (username,)
        c.execute(statement, args)
        result = c.fetchone()
        if result:
            stored_pw = result[2]
            authenticated = False
            authenticated = bcrypt.checkpw(password.encode('utf-8'), stored_pw.encode('utf-8'))
            if authenticated:
                session.clear()
                session['logged_in'] = True
                session['userid'] = result[0]
                session['username']=result[1]
                return redirect(url_for('index'))            
            else: error = "Wrong username or password!"
        else:
            error = "Wrong username or password!"
    return render_template('login.html',error=error)


@app.route("/register/", methods=('GET', 'POST'))
@limiter.limit(limit_value="5 per 5 minutes", error_message="Too many registrations, you can try again in 5 minutes.")
def register():
    errored = False
    usererror = ""
    passworderror = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if (username == "" or password == ""):
            usererror = "Please provide both username and password!"
            errored = True
        elif (len(username)>32 or len(password)>32):
            usererror = "Username and password must be less than 32 characters!"
            errored = True
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db = connect_db()
        c = db.cursor()
        """ Legacy vulnerable code:
        pass_statement = ""SELECT * FROM users WHERE password = '%s';"" %password
        user_statement = ""SELECT * FROM users WHERE username = '%s';"" %username
        c.execute(pass_statement)
        """
        """ Legacy vulnerable code
        pass_statement = ""SELECT * FROM users WHERE password = ?;""
        c.execute(pass_statement, (password,))
        if(len(c.fetchall())>0):
            errored = True
            passworderror = "That password is already in use by someone else!"
        """

        user_statement = """SELECT * FROM users WHERE username = ?;"""
        c.execute(user_statement, (username,)) 
        # c.execute(user_statement) Legacy vulnerable code
        if(len(c.fetchall())>0):
            errored = True
            usererror = "That username is already in use by someone else!"

        if(not errored):
            """ Legacy vulnerable code:
            statement = ""INSERT INTO users(id,username,password) VALUES(null,'%s','%s');"" %(username,password)
            print(statement)
            c.execute(statement)
            """ 
            statement = """INSERT INTO users(id,username,password) VALUES(null,?,?);"""
            print(statement)
            c.execute(statement, (username,pw_hash))
            db.commit()
            db.close()
            return f"""<html>
                        <head>
                            <meta http-equiv="refresh" content="2;url=/" />
                        </head>
                        <body>
                            <h1>SUCCESS!!! Redirecting in 2 seconds...</h1>
                        </body>
                        </html>
                        """
        
        db.commit()
        db.close()
    return render_template('register.html',usererror=usererror,passworderror=passworderror)


@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))

@app.route("/delete_user", methods=["POST"])
@login_required
def delete_user():
    user_id = session['userid']

    db = connect_db()
    c = db.cursor()
    statement = "DELETE FROM notes WHERE assocUser = ?"
    c.execute(statement, (user_id,))
    statement = "DELETE FROM users WHERE id = ?"
    c.execute(statement, (user_id,))
    db.commit()
    db.close()
    
    session.clear()
    return(redirect(url_for('index')))

@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    user_id = session['userid']
    new_password = request.form['newpassword']
    if new_password == "" or len(new_password)>32:
        return(render_template('notes.html', passwordchangeerror="Password must be between 1 and 32 characters!"))
    pw_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    db = connect_db()
    c = db.cursor()
    statement = "UPDATE users SET password = ? WHERE id = ?"
    c.execute(statement, (pw_hash, user_id))
    db.commit()
    db.close()

    return(render_template('notes.html', passwordchangesuccess="Password changed successfully!"))

if __name__ == "__main__":
    #create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5001 # 5001 is rerouted to 5000 via nginx
    if(len(sys.argv)==2):
        runport = sys.argv[1]
    try:
        app.run(host='0.0.0.0', port=runport, debug=False) # runs on machine ip address to make it visible on netowrk
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 5000)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")