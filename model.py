from flask_sqlalchemy import SQLAlchemy
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50), nullable=False)
	email = db.Column(db.String(100), nullable=False, unique=True)
	password = db.Column(db.String(250), nullable=False)
	
	key = db.Column(db.String(30), unique=True)

	spectacles = db.relationship("Spectacle", backref="user", lazy="select")

	def __init__(self, email, name, password):
		self.email = email
		self.name = name
		self.password = generate_password_hash(password)

class Spectacle(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(250), nullable=False)
	description = db.Column(db.String(250))
	photo_url = db.Column(db.String(120))
	time_to_expire = db.Column(db.Integer, nullable=False)
	time_to_display = db.Column(db.Integer, nullable=False)
	latitude = db.Column(db.Float, nullable=False)
	longitude = db.Column(db.Float, nullable=False)

	user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

	def __init__(self, title, description, photo_url, expiration, showtime, latitude, longitude):
		self.title = title
		self.description = description
		self.photo_url = photo_url
		self.time_to_expire = expiration
		self.time_to_display = showtime
		self.latitude = latitude
		self.longitude = longitude

		

	
