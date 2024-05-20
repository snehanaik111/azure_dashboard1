
from flask import Flask, request,render_template, redirect,session,url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crud.db'



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self,email,password,name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

class Crud(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100), unique=True)
    fuel_consumption = db.Column(db.Float) 


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(name=name,email=email,password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')



    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None  # Initialize error message variable

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            error = 'Please provide correct credentials to login.'  # Set error message

    return render_template('login.html', error=error)  # Pass error message to template



@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        crud_entries = Crud.query.all()
        labels = [entry.vehicle for entry in crud_entries]
        data = [float(entry.fuel_consumption) for entry in crud_entries]

        return render_template('dashboard.html', user=user, crud_entries=crud_entries, labels=labels, data=data)
   


        
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')

#new crud table


@app.route('/crud/create', methods=['POST'])
def crud_create():
    if request.method == 'POST':
        vehicle = request.form['vehicle']
        type = request.form['type']
        fuel_consumption = request.form['fuel_consumption']

        new_entry = Crud(vehicle=vehicle, type=type, fuel_consumption=fuel_consumption)
        db.session.add(new_entry)
        db.session.commit()
    return redirect('/dashboard')
    
@app.route('/crud/update/<int:id>', methods=['POST'])
def crud_update(id):
    if request.method == 'POST':
        entry = Crud.query.get_or_404(id)
        entry.vehicle = request.form['update_vehicle']
        entry.type = request.form['update_type']
        entry.fuel_consumption = request.form['update_fuel_consumption']
        db.session.commit()
        return redirect('/dashboard')  # Redirect to dashboard after updating entry

    return render_template('dashboard.html') 

@app.route('/add_crud', methods=['POST'])
def add_crud():
    if request.method == 'POST':
        vehicle = request.form['vehicle']
        type = request.form['type']
        fuel_consumption = request.form['fuel_consumption']

        new_entry = Crud(vehicle=vehicle, type=type, fuel_consumption=fuel_consumption)
        db.session.add(new_entry)
        db.session.commit()
        return redirect('/dashboard')  # Redirect to dashboard after adding entry

    return render_template('dashboard.html') 

@app.route('/crud/delete/<int:id>', methods=['POST'])
def crud_delete(id):
    if request.method == 'POST':
        entry = Crud.query.get_or_404(id)
        db.session.delete(entry)
        db.session.commit()
    return redirect('/dashboard')





if __name__ == '__main__':
    app.run(debug=True)