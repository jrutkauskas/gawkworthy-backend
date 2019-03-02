from flask import Flask, request, session, render_template, abort, url_for, redirect, flash, Response, jsonify
import datetime
import json

from flask_restful import Api, Resource
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from model import db, User, Spectacle

import os
app = Flask(__name__)
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
		return redirect(url_for("test_auth"))
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
				return redirect(url_for("test_auth"))

		else:
			flash("Error signing up new patron.  Need to complete all text boxes")
			return render_template("signup.html")
	
	flash("An unknown error occurred on signup attempt")
	return render_template("signup.html")	

@app.route("/api/spectacles", methods=["GET", "POST"])
@basic_auth
def spectacles_list():
	if request.method == "GET":
		spectacles_list = Spectacle.query.all()
		return jsonify(spectacles_list)
	elif request.method == "POST":
		data = request.get_json()
		print(data['latitude'])
		return "Success"
	return "unimplemented api for post"


@app.route("/post")
@basic_auth
def post_ui():
	return render_template("make_spectacle.html")

app.secret_key = "my secret key is better than yours"

if __name__ == "__main__":
	app.run(threaded=True, ssl_context='adhoc')

# CLI Commands
@app.cli.command("initdb")
def init_db():
	"""Initializes database and any model objects necessary"""
	db.drop_all()
	db.create_all()

	print("Initialized Database.")
	return

