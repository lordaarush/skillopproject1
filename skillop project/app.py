from flask import Flask, render_template,flash,redirect,request, url_for, session, logging,jsonify
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField ,PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)
# configure mysql
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'portfoliodb'
app.config['MYSQL_CURSORCLASS'] ='DictCursor'

mysql = MySQL(app)


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')

#form class
class RegisterForm(Form):
    name = StringField('Name',[validators.Length(min=1,max=50)])
    username = StringField('Username' ,[validators.Length(min=4,max=25)])
    email = StringField('Email',[validators.Length(min=6, max=50)])
    password = PasswordField('Password',[
        validators.DataRequired(),
        validators.EqualTo('confirm', message = 'Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

#user register
@app.route('/register', methods =['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        cur = mysql.connection.cursor()
        name = form.name.data
        email= form.email.data
        res1 = cur.execute('SELECT * FROM users WHERE email =%s',[email])
        #checking for email duping
        if res1>0:
            #email already exists!
            error="Email already registered!"
            return render_template('register.html',error=error,form=form)
        username=form.username.data
        res2 = cur.execute('SELECT * FROM users WHERE username =%s',[username])
        if res2>0:
            #username already exists!
            error="Username unavailable!"
            return render_template('register.html',error=error,form=form)
        password =  sha256_crypt.encrypt(str(form.password.data))
        
        cur.execute("INSERT INTO users(name,email,username,password) VALUES(%s,%s,%s,%s)",(name,email,username,password))            
        mysql.connection.commit()
        cur.close()

        flash("You have been registered and can now log in",'success')
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

#login
@app.route("/login",methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password_try = request.form['password']

        #cursor
        cur = mysql.connection.cursor()

        result = cur.execute('SELECT * FROM users WHERE username =%s',[username])

        if result>0:
            #get hashed pass
            d = cur.fetchone()
            password  = d['password']

            #check pass
            if sha256_crypt.verify(password_try,password):
                #Authenitcation passed
                session['logged_in'] = True
                session['username'] = username

                flash("You are now logged in!", 'success')
                return redirect(url_for('portfolio'))

            else:
                error = "Incorrect password"
                return render_template("login.html",error=error)
            #close connection to db
            cur.close()
        else:
            error = "Username not found"
            return render_template("login.html",error=error)
    return render_template('login.html')

#check if user logged in 
def is_logged_in(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash('Unauthorised, please login!','danger')
            return redirect(url_for('login'))
    return wrap


#logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully','success')
    return redirect(url_for('login'))

#search
'''@app.route('/livesearch',methods=["POST","GET"])
def livesearch():
    searchbox = request.form.get('text')
    cur = mysql.connection.cursor()
    query ="select name,username from users where username like'{}%'".format(searchbox)
    cur.execute(query)
    result = cur.fetchall()
    return jsonify(result)'''
#profile
@app.route("/portfolio",methods=["POST","GET"])
@is_logged_in
def portfolio():
    #print("%s"%({{session.username}}))
    '''if request.method=='POST':
        #branch = request.form['branch']
        #year= request.form['year']
        return render_template('updateprofile.html')'''
    return render_template('profile.html')

    


#finish profile
'''@app.route('/updateprofile',methods=['GET','POST'])
@is_logged_in
def updateprofile():
     return render_template('updateprofile.html')'''

if __name__ == '__main__':
    app.secret_key="SECRET123"
    app.run(debug =True)