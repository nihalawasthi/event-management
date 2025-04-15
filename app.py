# app.py
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TimeField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.String(10), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref='events')

# Forms
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=150)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=150)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("Username already exists.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=150)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=150)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

class EventForm(FlaskForm):
    name = StringField('Event Name', validators=[InputRequired()])
    date = DateField('Event Date', validators=[InputRequired()])
    time = TimeField('Event Time', validators=[InputRequired()])
    location = StringField('Event Location', validators=[InputRequired()])
    submit = SubmitField('Add Event')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('view_events'))
        flash("Invalid username or password.", "danger")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_event():
    form = EventForm()
    if form.validate_on_submit():
        event_time = form.time.data
        event_time = event_time.strftime("%H:%M:%S")
        new_event = Event(
            name=form.name.data,
            date=form.date.data,
            time=event_time,
            location=form.location.data,
            creator_id=current_user.id
        )
        db.session.add(new_event)
        db.session.commit()
        flash("Event added successfully!", "success")
        return redirect(url_for('view_events'))
    return render_template('add_event.html', form=form)

@app.route('/events')
def view_events():
    query = request.args.get('q')
    if query:
        events = Event.query.filter(Event.name.contains(query)).order_by(Event.date.asc()).all()
    else:
        events = Event.query.order_by(Event.date.asc()).all()
    return render_template('view_events.html', events=events, query=query)

@app.route('/edit/<int:event_id>', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.creator_id != current_user.id:
        flash("You are not authorized to edit this event.", "danger")
        return redirect(url_for('view_events'))
    if request.method == 'POST':
        event.name = request.form['name']
        event.date = request.form['date']
        event.time = request.form['time']
        event.location = request.form['location']
        db.session.commit()
        flash("Event updated successfully!", "success")
        return redirect(url_for('view_events'))
    return render_template('edit_event.html', event=event)

@app.route('/delete/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    if event.creator_id != current_user.id:
        flash("You are not authorized to delete this event.", "danger")
        return redirect(url_for('view_events'))
    db.session.delete(event)
    db.session.commit()
    flash("Event deleted successfully.", "success")
    return redirect(url_for('view_events'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
