from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()


class User(UserMixin, db.Model):
	__tablename__ = "users"
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
	name = db.Column(db.String(120), nullable=False)
	email = db.Column(db.String(255), unique=True, nullable=False, index=True)
	phone = db.Column(db.String(10), nullable=False)
	address = db.Column(db.Text, nullable=False)
	password_hash = db.Column(db.String(255), nullable=False)
	avatar_data = db.Column(db.LargeBinary, nullable=True)  # Store avatar image as binary
	avatar_mimetype = db.Column(db.String(32), nullable=True)  # Store mimetype of the avatar
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

	todos = db.relationship("Todo", backref="owner", lazy=True, cascade="all, delete-orphan")

	def set_password(self, password: str) -> None:
		self.password_hash = generate_password_hash(password)

	def check_password(self, password: str) -> bool:
		return check_password_hash(self.password_hash, password)


class Todo(db.Model):
	__tablename__ = "todos"
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
	title = db.Column(db.String(255), nullable=False)
	description = db.Column(db.Text, nullable=True)
	is_completed = db.Column(db.Boolean, default=False, nullable=False)
	created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
	updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
