import re
import os
from pathlib import Path
from datetime import datetime, timedelta
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from email_validator import validate_email, EmailNotValidError
from werkzeug.utils import secure_filename
import imghdr

from config import Config
from models import db, User, Todo

ALLOWED_AVATAR_EXTS = {"png", "jpg", "jpeg", "webp"}


def create_app() -> Flask:
	app = Flask(__name__)
	app.config.from_object(Config)

	# Accept routes with or without trailing slashes to avoid 405 on POST redirects
	app.url_map.strict_slashes = False
	
	# Configure session timeout
	app.permanent_session_lifetime = timedelta(seconds=app.config['PERMANENT_SESSION_LIFETIME'])

	db.init_app(app)
	
	@app.after_request
	def add_cache_headers(response):
		# Prevent caching of authenticated pages
		if current_user.is_authenticated:
			response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
			response.headers["Pragma"] = "no-cache"
			response.headers["Expires"] = "0"
		return response

	login_manager = LoginManager(app)
	login_manager.login_view = "login"

	@login_manager.user_loader
	def load_user(user_id):
		return db.session.get(User, int(user_id))

	with app.app_context():
		db.drop_all()  # This will drop all existing tables
		db.create_all()  # This will create new tables with the updated schema

	@app.route('/avatar/<int:user_id>')
	def get_avatar(user_id):
		user = User.query.get_or_404(user_id)
		if user.avatar_data is None:
			return redirect(url_for('static', filename='images/default-avatar.png'))
		return send_file(
			BytesIO(user.avatar_data),
			mimetype=user.avatar_mimetype
		)

	@app.context_processor
	def inject_avatar_url():
		if current_user.is_authenticated:
			return {"avatar_url": url_for('get_avatar', user_id=current_user.id)}
		return {"avatar_url": None}

	@app.route("/")
	def index():
		if current_user.is_authenticated:
			return redirect(url_for("todos"))
		return render_template("home.html")

	# ---------- Auth Routes ----------
	@app.route("/signup", methods=["GET", "POST"])
	def signup():
		# Debug: log incoming requests to help diagnose Method Not Allowed errors
		app.logger.debug(f"signup called: method={request.method} path={request.path}")
		if request.method == "POST":
			user_id = request.form.get("user_id", "").strip()
			name = request.form.get("name", "").strip()
			email = request.form.get("email", "").strip()
			phone = request.form.get("phone", "").strip()
			address = request.form.get("address", "").strip()
			password = request.form.get("password", "")
			confirm_password = request.form.get("confirm_password", "")

			# Server-side validation
			errors = []
			if not user_id:
				errors.append("User ID is required.")
			if not name:
				errors.append("Name is required.")
			if not email:
				errors.append("Email is required.")
			else:
				try:
					validate_email(email, check_deliverability=False)
				except EmailNotValidError:
					errors.append("Invalid email address.")
			if not phone:
				errors.append("Phone number is required.")
			elif not re.match(r'^\d{10}$', phone):
				errors.append("Please enter a valid 10-digit phone number.")
			if not address:
				errors.append("Address is required.")
			if not password:
				errors.append("Password is required.")
			if password != confirm_password:
				errors.append("Passwords do not match.")
			if password and len(password) < 6:
				errors.append("Password must be at least 6 characters.")
			if not re.match(r"^[A-Za-z0-9_\-\.]{3,64}$", user_id or ""):
				errors.append("User ID must be 3-64 chars: letters, numbers, _ - .")

			if User.query.filter((User.user_id == user_id) | (User.email == email)).first():
				errors.append("User ID or Email already exists.")

			if errors:
				for e in errors:
					flash(e, "error")
				return render_template("signup.html")

			user = User(user_id=user_id, name=name, email=email, phone=phone, address=address)
			user.set_password(password)
			db.session.add(user)
			db.session.commit()
			flash("Successfully signed up! Please log in.", "success")
			return redirect(url_for("login"))

		return render_template("signup.html")

	@app.route("/login", methods=["GET", "POST"])
	def login():
		# Debug: log incoming requests to help diagnose Method Not Allowed errors
		app.logger.debug(f"login called: method={request.method} path={request.path}")
		if request.method == "POST":
			user_id = request.form.get("user_id", "").strip()
			password = request.form.get("password", "")

			if not user_id or not password:
				flash("User ID and Password are required.", "error")
				return render_template("login.html")

			user = User.query.filter_by(user_id=user_id).first()
			if not user or not user.check_password(password):
				flash("Invalid credentials.", "error")
				return render_template("login.html")

			login_user(user)
			session.permanent = True  # Use permanent session with timeout
			return redirect(url_for("todos"))

		return render_template("login.html")

	@app.route("/logout")
	@login_required
	def logout():
		logout_user()
		session.clear()  # Clear all session data
		flash("Logged out.", "info")
		response = redirect(url_for("index"))
		# Clear cache control headers
		response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
		response.headers["Pragma"] = "no-cache"
		response.headers["Expires"] = "0"
		return response

	@app.route("/forgot-password", methods=["GET", "POST"])
	def forgot_password():
		# Debug: log incoming requests to help diagnose Method Not Allowed errors
		app.logger.debug(f"forgot_password called: method={request.method} path={request.path}")
		if request.method == "POST":
			user_id = request.form.get("user_id", "").strip()
			email = request.form.get("email", "").strip()
			new_password = request.form.get("new_password", "")
			confirm_password = request.form.get("confirm_password", "")

			errors = []
			if not user_id:
				errors.append("User ID is required.")
			if not email:
				errors.append("Email is required.")
			else:
				try:
					validate_email(email, check_deliverability=False)
				except EmailNotValidError:
					errors.append("Invalid email address.")
			if not new_password:
				errors.append("New password is required.")
			if new_password != confirm_password:
				errors.append("Passwords do not match.")
			if new_password and len(new_password) < 6:
				errors.append("Password must be at least 6 characters.")

			if errors:
				for e in errors:
					flash(e, "error")
				return render_template("forgot_password.html")

			user = User.query.filter_by(user_id=user_id, email=email).first()
			if not user:
				flash("User not found with provided User ID and Email.", "error")
				return render_template("forgot_password.html")

			user.set_password(new_password)
			db.session.commit()
			flash("Password updated. Please log in.", "success")
			return redirect(url_for("login"))

		return render_template("forgot_password.html")

	# ---------- Profile & Avatar Routes ----------
	@app.route("/profile", methods=["GET", "POST"])
	@login_required
	def profile():
		# Debug: log incoming requests to help diagnose Method Not Allowed errors
		app.logger.debug(f"profile called: method={request.method} path={request.path}")
		if request.method == "POST":
			intent = request.form.get("intent")
			if intent == "update_profile":
				name = request.form.get("name", "").strip()
				email = request.form.get("email", "").strip()
				errors = []
				if not name:
					errors.append("Name is required.")
				if not email:
					errors.append("Email is required.")
				else:
					try:
						validate_email(email, check_deliverability=False)
					except EmailNotValidError:
						errors.append("Invalid email address.")
				# unique email, excluding current user
				existing = User.query.filter(User.email == email, User.id != current_user.id).first()
				if existing:
					errors.append("Email already in use.")
				if errors:
					for e in errors:
						flash(e, "error")
				else:
					current_user.name = name
					current_user.email = email
					db.session.commit()
					flash("Profile updated.", "success")
			elif intent == "change_password":
				current_password = request.form.get("current_password", "")
				new_password = request.form.get("new_password", "")
				confirm_password = request.form.get("confirm_password", "")
				errors = []
				if not current_password or not new_password or not confirm_password:
					errors.append("All password fields are required.")
				elif not current_user.check_password(current_password):
					errors.append("Current password is incorrect.")
				if new_password and len(new_password) < 6:
					errors.append("New password must be at least 6 characters.")
				if new_password != confirm_password:
					errors.append("New passwords do not match.")
				if errors:
					for e in errors:
						flash(e, "error")
				else:
					# Update password and force re-login for security
					current_user.set_password(new_password)
					db.session.commit()
					flash("Password updated successfully. Please log in again.", "success")
					# Log the user out so they must re-authenticate with the new password
					logout_user()
					session.clear()
					return redirect(url_for("login"))
			return redirect(url_for("profile"))
		return render_template("profile.html")

	@app.route("/profile/avatar", methods=["POST"])
	@login_required
	def upload_avatar():
		file = request.files.get('avatar')
		if not file or file.filename.strip() == "":
			flash("Please choose an image to upload.", "error")
			return redirect(url_for('profile'))
		
		# Read the file data
		file_data = file.read()
		
		# Verify it's a valid image file
		file_type = imghdr.what(None, h=file_data)
		if not file_type or file_type.lower() not in ALLOWED_AVATAR_EXTS:
			flash("Unsupported image type. Use PNG, JPG, JPEG, or WEBP.", "error")
			return redirect(url_for('profile'))
		
		try:
			# Store the image data in the database
			current_user.avatar_data = file_data
			current_user.avatar_mimetype = file.content_type
			db.session.commit()
			flash("Avatar updated.", "success")
		except Exception as e:
			flash("Failed to save avatar.", "error")
			
		return redirect(url_for('profile'))

	# ---------- Todo Routes ----------
	@app.route("/todos")
	@login_required
	def todos():
		items = (
			Todo.query.filter_by(user_id=current_user.id)
			.order_by(Todo.created_at.desc())
			.all()
		)
		return render_template("todos.html", items=items)

	@app.route("/todos", methods=["POST"])
	@login_required
	def create_todo():
		title = request.form.get("title", "").strip()
		description = request.form.get("description", "").strip()
		if not title:
			flash("Title is required.", "error")
			return redirect(url_for("todos"))
		todo = Todo(user_id=current_user.id, title=title, description=description)
		db.session.add(todo)
		db.session.commit()
		flash("Todo created.", "success")
		return redirect(url_for("todos"))

	@app.route("/todos/<int:todo_id>/toggle", methods=["POST"]) 
	@login_required
	def toggle_todo(todo_id: int):
		todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
		todo.is_completed = not todo.is_completed
		db.session.commit()
		if request.headers.get("X-Requested-With") == "XMLHttpRequest":
			return jsonify({"ok": True, "is_completed": todo.is_completed})
		flash("Todo updated.", "success")
		return redirect(url_for("todos"))

	@app.route("/todos/<int:todo_id>/delete", methods=["POST"]) 
	@login_required
	def delete_todo(todo_id: int):
		todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
		db.session.delete(todo)
		db.session.commit()
		if request.headers.get("X-Requested-With") == "XMLHttpRequest":
			return jsonify({"ok": True})
		flash("Todo deleted.", "success")
		return redirect(url_for("todos"))

	@app.route("/todos/<int:todo_id>", methods=["POST"]) 
	@login_required
	def update_todo(todo_id: int):
		# Handles inline edit via form
		title = request.form.get("title", "").strip()
		description = request.form.get("description", "").strip()
		if not title:
			flash("Title is required.", "error")
			return redirect(url_for("todos"))
		todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first_or_404()
		todo.title = title
		todo.description = description
		db.session.commit()
		flash("Todo updated.", "success")
		return redirect(url_for("todos"))

	return app


if __name__ == "__main__":
	app = create_app()
	app.run(host="127.0.0.1", port=5000, debug=True)
