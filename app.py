from flask import Flask, request,render_template, redirect,session,url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crud.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///level_sensor_data.db'


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
    fuel_consumption = db.Column(db.String(100))


class LevelSensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(100))
    full_addr = db.Column(db.String(100))
    sensor_data = db.Column(db.String(100))
    imei = db.Column(db.String(100))

    def __repr__(self):
        return f"<LevelSensorData(date='{self.date}', full_addr='{self.full_addr}', sensor_data={self.sensor_data}, imei='{self.imei}')>"




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

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Check if all required fields are present
    if not name or not email or not password:
        return jsonify({"message": "Please provide name, email, and password"}), 400

    try:
        if User.query.filter_by(email=email).first():
            return jsonify({"message": "Email already registered"}), 400

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

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

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data['email']
    password = data['password']

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['email'] = user.email
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        crud_entries = Crud.query.all()
        labels = [entry.vehicle for entry in crud_entries]
        data = [float(entry.fuel_consumption) for entry in crud_entries]
        sense_data = LevelSensorData.query.all()

        return render_template('dashboard.html', user=user, crud_entries=crud_entries, labels=labels, data=data,sense_data=sense_data)
   


        
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('email', None)
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    else:
        return jsonify({"message": "User not found"}), 404



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

@app.route('/api/crud', methods=['GET'])
def api_get_all_crud_entries():
    entries = Crud.query.all()
    entries_data = [{"id": entry.id, "vehicle": entry.vehicle, "type": entry.type, "fuel_consumption": entry.fuel_consumption} for entry in entries]
    return jsonify(entries_data), 200

@app.route('/api/crud/create', methods=['POST'])
def api_create_crud_entry():
    data = request.json
    vehicle = data.get('vehicle')
    type = data.get('type')
    fuel_consumption = data.get('fuel_consumption')

    # Check if all required fields are present
    if not vehicle or not type or not fuel_consumption:
        return jsonify({"message": "Please provide vehicle, type, and fuel_consumption"}), 400

    try:
        new_entry = Crud(vehicle=vehicle, type=type, fuel_consumption=fuel_consumption)
        db.session.add(new_entry)
        db.session.commit()
        return jsonify({"message": "Entry created successfully"}), 201
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@app.route('/api/crud/<int:id>', methods=['GET', 'PUT', 'DELETE'])
def api_crud_entry(id):
    entry = Crud.query.get_or_404(id)

    if request.method == 'GET':
        entry_data = {"id": entry.id, "vehicle": entry.vehicle, "type": entry.type, "fuel_consumption": entry.fuel_consumption}
        return jsonify(entry_data), 200

    elif request.method == 'PUT':
        data = request.json
        entry.vehicle = data['vehicle']
        entry.type = data['type']
        entry.fuel_consumption = data['fuel_consumption']
        db.session.commit()
        return jsonify({"message": "Entry updated successfully"}), 200

    elif request.method == 'DELETE':
        db.session.delete(entry)
        db.session.commit()
        return jsonify({"message": "Entry deleted successfully"}), 200


@app.route('/level_sensor_data', methods=['POST'])
def receive_level_sensor_data():
    if request.method == 'POST':
        sense_data = request.json
# if therre is commma , mean sensor value (if() {val = split value by , and get first} )


        # Extracting data from JSON
        date = sense_data.get('D', '')
        full_addr = sense_data.get('address', '')
        sensor_data = sense_data.get('data', '')
        imei = sense_data.get('IMEI', '')

        # Create a new LevelSensorData object and add it to the database
        new_data = LevelSensorData(date=date, full_addr=full_addr, sensor_data=sensor_data, imei=imei)
        db.session.add(new_data)
        db.session.commit()

        # Return a response
        response = {'status': 'success', 'message': 'Data received and stored successfully'}
        return jsonify(response), 200
    return redirect('/dashboard')

if __name__ == '__main__':
    app.run(debug=True)
