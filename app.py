from flask import Flask, request, session, render_template, abort, url_for, redirect, flash, Response, jsonify
import datetime
import json

from flask_restful import Api, Resource
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from model import db, User, Spectacle
import secrets
import time

import os
app = Flask(__name__)

f=open(".env", "r")
env = json.loads(f.read())

#app.config["SQLALCHEMY_DATABASE_URI"] =  "mysql+pymysql://root:" + env['dbpass'] +"@" +env['dbip'] +"/?unix_socket=/cloudsql/" + env['instance'] #"sqlite:///" + os.path.join(
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
	app.root_path, "gawkworthy.db"
)
# Suppress deprecation warning
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 1
api = Api(app, prefix="/api")
db.init_app(app)


def basic_auth(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		auth = request.authorization
		if not auth:
			return authenticate()
		if not check_auth(auth.username, auth.password):
			return authenticate()
		session["email"] = auth.username
		return f(*args, **kwargs)
	return decorated

def check_auth(email=None, password=None):
	if not email or not password:
		return False
	
	u = User.query.filter_by(email=email).first()
	if u and check_password_hash(u.password,password):
		return True
	else:
		return False

def authenticate():
	"""Sends a 401 response that enables basic auth"""
	return Response(
	'Could not verify your access level for that URL.\n'
	'You have to login with proper credentials', 401,
	{'WWW-Authenticate': 'Basic realm="Login Required"'})

@app.route("/")
def home():
	return "hello world"

@app.route("/auth")
@basic_auth
def test_auth():
	
	return "Authorized " + session["email"]

@app.route("/signup/", methods=["GET", "POST"])
def sign_up():
	if "email" in session:
		return redirect("/map")
	elif request.method == "GET":
		return render_template("signup.html")
	elif request.method == "POST":
		if "name" in request.form and len(request.form["name"]) > 0 and "user" in request.form and len(request.form["user"]) > 0 and "pass" in request.form and len(request.form["pass"]) > 0:
			#register user
			if User.query.filter_by(email=request.form["user"]).first():
				flash("That email is already taken.  Please choose a different one.")
				return render_template("signup.html")
			else:
				new_user = User(request.form["user"], request.form["name"], request.form["pass"])
				
				db.session.add(new_user)

				db.session.commit()

				flash("Signed up new user: %s.  Please log in to your new account." % request.form["user"])
				return redirect("/map")

		else:
			flash("Error signing up new patron.  Need to complete all text boxes")
			return render_template("signup.html")
	
	flash("An unknown error occurred on signup attempt")
	return render_template("signup.html")	

@app.route('/logout')
def logout():
	if "email" in session:
		# note, here were calling the .clear() method for the python dictionary builtin
		session.clear()
		# flashes are stored in session["_flashes"], so we need to clear the session /before/ we set the flash message!
		flash("Successfully logged out!")

		return redirect(url_for("login"))
	else:
		flash("Not currently logged in!")
		return redirect(url_for("login"))

@app.route("/api/spectacles", methods=["GET", "POST"])
def spectacles_list():
	if not "email" in session:
		return Response("Not logged in", 401)
	if request.method == "GET":
		current_time = time.time()*1000.0
		q = Spectacle.query.filter(Spectacle.time_to_display <= current_time, Spectacle.time_to_expire >= current_time)
		print(request.args.get("minlat"))
		if request.args.get('minlat'):
			q = q.filter(Spectacle.latitude >= request.args.get('minlat', default = '*', type = float))
		if request.args.get('maxlat'):
			q = q.filter(Spectacle.latitude <= request.args.get('maxlat', default = '*', type = float))
		if request.args.get('minlon'):
			q = q.filter(Spectacle.longitude >= request.args.get('minlon', default = '*', type = float))
		if request.args.get('maxlon'):
			q = q.filter(Spectacle.longitude <= request.args.get('maxlon', default = '*', type = float))
		spectacles_list = q.all()
		return json.dumps([{"latitude":s.latitude, 
			"longitude":s.longitude,
			"title":s.title,
			"photo_url":s.photo_url,
			"description":s.description,
			"expiration":s.time_to_expire,
			"showtime":s.time_to_display} for s in spectacles_list])
	elif request.method == "POST":
		data = request.get_json()
		u = User.query.filter_by(email=session['email']).first()
		s = Spectacle(
			data['title'],
			data['description'],
			data['photo_url'],
			data['expiration'],
			data['showtime'],
			data['latitude'],
			data['longitude']
		)
		db.session.add(s)
		u.spectacles.append(s)
		db.session.commit()
		return "Success"
	return "unsupported"

@app.route("/api/signin", methods=["POST"])
def get_token():
	data = request.get_json()
	if "email" in data and "password" in data:
		token = secrets.token_urlsafe(16)
		u = User.query.filter_by(email=data['email']).first()
		if u and check_password_hash(u.password, data['password']):
			u.key = token
			return token
		else:
			return Response('Username or Password Incorrect\n', 401)
	else:
		return Response('Unauthorized.\n', 401)

@app.route("/post")
def post_ui():
	if "email" in session:
		return render_template("make_spectacle.html")
	else:
		return redirect("/login")

@app.route('/login', methods=["GET", "POST"])
def login():
	if "email" in session:
		flash("Already Logged In!")
		return redirect("/map")

	elif request.method == "POST":
		username = request.form["user"]
		password = request.form["pass"]

		if username and password:
			user = User.query.filter_by(email=username).first()
			if not user or not check_password_hash(user.password, password):
				flash("Incorrect Username or password")
			else:
				session["email"] = username
				return redirect("/map")
				
		else:
			flash("An error occurred logging you in")

	return render_template("login.html")

@app.route('/map')
def map_ui():
	if not "email" in session:
		return redirect("/login")
	return render_template('map.html')



app.secret_key = "my secret key is better than yours"

if __name__ == "__main__":
	app.run(threaded=True)



# CLI Commands
@app.cli.command("initdb")
def init_db():
	"""Initializes database and any model objects necessary"""
	db.drop_all()
	db.create_all()

	print("Initialized Database.")
	return

