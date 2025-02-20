from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), nullable=False, unique=True)
    dob = db.Column(db.String(10), nullable=False)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Donate(db.Model):

    __tablename__ = "donate"

    aadhaar = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.String(100))
    weight = db.Column(db.Integer)
    gender = db.Column(db.String(100))
    address = db.Column(db.String(100))
    bloodgroup = db.Column(db.String(100))

    def __repr__(self):
        return f"Aadhaar: {self.aadhaar} Name: {self.name} Age: {self.age} Weight: {self.weight} Gender: {self.gender} Address: {self.address} Blood Group:  {self.bloodgroup}"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        dob = request.form['dob']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or Email already exists!', 'danger')
            return redirect(url_for('register'))

        new_user = User(first_name=first_name, last_name=last_name, email=email, dob=dob, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can log in now.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))



@app.route("/donate", methods=["GET", "POST"])
@login_required
def donate():

    if request.method == "POST":
        aadhaar = request.form.get("aadhaar")
        name = request.form.get("name")
        age = request.form.get("age")
        weight = request.form.get("weight")
        gender = request.form.get("gender")
        address = request.form.get("address")
        bloodgroup = request.form.get("bloodgroup")

        donate = Donate(name=name, aadhaar=aadhaar, age=age, weight=weight, gender=gender, address=address, bloodgroup=bloodgroup)
        db.session.commit()  
        db.session.add(donate)
        
        
        return redirect(url_for('home'))
    return render_template('donate.html')

    donate = Donate.query.all()
    return render_template("donate.html")

@app.route('/about')
def about():
    return render_template('aboutus.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)