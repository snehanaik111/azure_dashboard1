from flask import Flask, request,render_template, redirect,session,url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import logging
import json


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
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    date = db.Column(db.String(50))
    full_addr = db.Column(db.Integer)
    sensor_data = db.Column(db.Float)
    imei = db.Column(db.String(50))

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

        filter_option = request.args.get('filter', 'latest')
        page = request.args.get('page', 1, type=int)

        # Check if there is a search query parameter
        search_query = request.args.get('query')
        if search_query:
            sense_data_pagination = LevelSensorData.query.filter(
                (LevelSensorData.date.like(f'%{search_query}%')) |
                (LevelSensorData.full_addr.like(f'%{search_query}%')) |
                (LevelSensorData.sensor_data.like(f'%{search_query}%')) |
                (LevelSensorData.imei.like(f'%{search_query}%'))
            ).order_by(LevelSensorData.date.desc()).paginate(page=page, per_page=10)
        else:
            if filter_option == 'oldest':
                sense_data_pagination = LevelSensorData.query.order_by(LevelSensorData.date.asc()).paginate(page=page, per_page=10)
            else:
                sense_data_pagination = LevelSensorData.query.order_by(LevelSensorData.date.desc()).paginate(page=page, per_page=10)

        sense_data = sense_data_pagination.items

        return render_template(
            'dashboard.html',
            user=user,
            crud_entries=crud_entries,
            labels=labels,
            data=data,
            sense_data=sense_data,
            filter_option=filter_option,
            pagination=sense_data_pagination
        )

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





logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')



# Configure a separate logger for API calls
api_logger = logging.getLogger('api_logger')
api_handler = logging.FileHandler('apilog.txt')
api_handler.setLevel(logging.INFO)
api_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
api_logger.addHandler(api_handler)




@app.route('/level_sensor_data', methods=['POST'])
def receive_level_sensor_data():
    if request.method == 'POST':
        try:
            if not request.is_json:
                api_logger.error("Request content type is not JSON")
                return jsonify({'status': 'failure', 'message': 'Request content type is not JSON'}), 400

            request_data = request.json

            # Ensure modbus_TEST field is present
            modbus_test_data = request_data.get('modbus_TEST', {})
            date = modbus_test_data.get('D', '')
            full_addr = modbus_test_data.get('address', 0)
            sensor_data = modbus_test_data.get('data')
            imei = modbus_test_data.get('IMEI', '')

            # Check if all required fields are present
            if not all([date, full_addr, sensor_data, imei]):
                api_logger.error("Missing required data fields")
                return jsonify({'status': 'failure', 'message': 'Missing required data fields'}), 400

            # Attempt to convert sensor_data to float
            try:
                sensor_data = float(sensor_data)
            except ValueError:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Create a new LevelSensorData object and add it to the database
            new_data = LevelSensorData(date=date, full_addr=full_addr, sensor_data=sensor_data, imei=imei)
            db.session.add(new_data)
            db.session.commit()

            # Log success
            logging.info("Data stored successfully: %s", request_data)

            # Return a response
            response = {'status': 'success', 'message': 'Data received and stored successfully'}
            return jsonify(response), 200

        except Exception as e:
            # Log failure
            logging.error("Failed to store data: %s", e)
            return jsonify({'status': 'failure', 'message': 'Failed to store data'}), 500

    logging.info("Received non-POST request at /level_sensor_data, redirecting to /dashboard")
    return redirect('/dashboard')






# API route to get the count of device entries logged
@app.route('/api/device_entries_logged', methods=['GET'])
def api_device_entries_logged():
    if 'email' in session:
        # Count the number of entries in the LevelSensorData table
        count = LevelSensorData.query.count()
        return jsonify({"device_entries_logged": count}), 200
    return jsonify({"message": "Unauthorized"}), 401

# API route to get the count of active devices
@app.route('/api/no_of_devices_active', methods=['GET'])
def api_no_of_devices_active():
    if 'email' in session:
        # Count the number of distinct IMEI values in the LevelSensorData table
        active_devices = db.session.query(db.func.count(db.distinct(LevelSensorData.imei))).scalar()
        return jsonify({"no_of_devices_active": active_devices}), 200
    return jsonify({"message": "Unauthorized"}), 401


@app.route('/search', methods=['GET'])
def search_sensor_data():
    query = request.args.get('query')
    page = request.args.get('page', 1, type=int)  # Get the page number from the request

    if query:
        sense_data_pagination = LevelSensorData.query.filter(
            (LevelSensorData.date.like(f'%{query}%')) |
            (LevelSensorData.full_addr.like(f'%{query}%')) |
            (LevelSensorData.sensor_data.like(f'%{query}%')) |
            (LevelSensorData.imei.like(f'%{query}%'))
        ).paginate(page=page, per_page=10)
        sense_data = sense_data_pagination.items  # Extract items from pagination object
    else:
        sense_data_pagination = LevelSensorData.query.paginate(page=page, per_page=10)
        sense_data = sense_data_pagination.items  # Extract items from pagination object
    
    user = User.query.filter_by(email=session.get('email')).first()  # Use get to avoid KeyError
    crud_entries = Crud.query.all()
    labels = [entry.vehicle for entry in crud_entries]
    data = [float(entry.fuel_consumption) for entry in crud_entries]

    return render_template('dashboard.html', user=user, crud_entries=crud_entries, labels=labels, data=data, sense_data=sense_data, pagination=sense_data_pagination)

if __name__ == '__main__':
    app.run(debug=True)
