from flask import Flask, request,render_template, redirect,session,url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import logging
import json


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'





import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()

# Create the conversion table
cursor.execute('''
CREATE TABLE IF NOT EXISTS conversion_table (
    sensor_data INTEGER PRIMARY KEY,
    volume_liters REAL
)
''')

# Insert sample data into the conversion table
conversion_data = [
    (240, 8.875),
    (234, 8.625),
    (228, 8.375),
    (222, 8.125),
    (215, 7.875),
    (209, 7.625),
    (203, 7.375),
    (197, 7.125),
    (196, 7.125),
    (190, 6.875),
    (183, 6.625),
    (177, 6.375),
    (170, 6.125),
    (164, 5.875),
    (158, 5.625),
    (151, 5.375),
    (152, 5.375),
    (144, 5.125),
    (138, 4.875),
    (131, 4.625),
    (125, 4.375),
    (118, 4.125),
    (111, 3.875),
    (105, 3.625),
    (98, 3.375),
    (91, 3.125),
    (85, 2.875),
    (78, 2.625),
    (71, 2.375),
    (70, 2.225),
    (64, 2.125),
    (57, 1.875),
    (50, 1.625),
    (51, 1.625),
    (42, 1.375),
    (35, 1.125),
    (28, 0.875),
    (21, 0.625),
    (19, 0.696),
    (14, 0.375),
    (6, 0.125),
    (0, 0)
]

cursor.executemany('''
INSERT OR IGNORE INTO conversion_table (sensor_data, volume_liters)
VALUES (?, ?)
''', conversion_data)

# Commit and close the connection
conn.commit()
conn.close()

















class ConversionTable(db.Model):
    sensor_data = db.Column(db.Integer, primary_key=True)
    volume_liters = db.Column(db.Float)

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




class LevelSensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    date = db.Column(db.String(50))
    full_addr = db.Column(db.Integer)
    sensor_data = db.Column(db.Float)
    imei = db.Column(db.String(50))
    volume_liters = db.Column(db.Float)  # New column for converted volumes

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

        # Apply conversion logic to calculate volumes in liters for each data point
        for data_point in sense_data:
            data_point.volume_liters = get_volume(data_point.sensor_data)

        return render_template(
            'dashboard.html',
            user=user,
           
            sense_data=sense_data,
            filter_option=filter_option,
            pagination=sense_data_pagination,
           
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

            request_data = request.get_json()

            # Ensure modbus_TEST field is present and parse its value as JSON
            modbus_test_data = request_data.get('modbus_TEST', '{}')
            try:
                sense_data = json.loads(modbus_test_data)
            except json.JSONDecodeError:
                api_logger.error("Invalid JSON format in modbus_TEST")
                return jsonify({'status': 'failure', 'message': 'Invalid JSON format in modbus_TEST'}), 400

            api_logger.info("API called with data: %s", sense_data)

            # Extracting data from JSON
            date = sense_data.get('D', '')
            full_addr = sense_data.get('address', 0)
            sensor_data = sense_data.get('data', [])
            imei = sense_data.get('IMEI', '')

            if not all([date, full_addr, sensor_data, imei]):
                api_logger.error("Missing required data fields")
                return jsonify({'status': 'failure', 'message': 'Missing required data fields'}), 400

            # Ensure sensor_data is a list and extract the first element
            if isinstance(sensor_data, list) and sensor_data:
                sensor_data = sensor_data[0]
            else:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Convert sensor_data to float
            try:
                sensor_data = float(sensor_data)
            except ValueError:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Create a new LevelSensorData object and add it to the database
            volume_liters = get_volume(sensor_data)
            new_data = LevelSensorData(date=date, full_addr=full_addr, sensor_data=sensor_data, imei=imei,volume_liters=volume_liters)
            db.session.add(new_data)
            db.session.commit()

            # Log success
            logging.info("Data stored successfully: %s", json.dumps(sense_data))

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
 # Apply conversion logic to calculate volumes in liters for each data point
    for data_point in sense_data:
        data_point.volume_liters = get_volume(data_point.sensor_data)

    return render_template('dashboard.html', user=user, sense_data=sense_data, pagination=sense_data_pagination)



# Fetch the volume from the conversion table
def get_volume(sensor_data):
    conversion_entry = ConversionTable.query.filter_by(sensor_data=int(sensor_data)).first()
    if conversion_entry:
        return conversion_entry.volume_liters
    else:
        numeric_keys = [entry.sensor_data for entry in ConversionTable.query.all()]
        lower_key = max(key for key in numeric_keys if key < sensor_data)

        upper_keys = [key for key in numeric_keys if key > sensor_data]
        if upper_keys:
            upper_key = min(upper_keys)
            lower_volume = ConversionTable.query.filter_by(sensor_data=lower_key).first().volume_liters
            upper_volume = ConversionTable.query.filter_by(sensor_data=upper_key).first().volume_liters
            interpolated_volume = interpolate(lower_key, lower_volume, upper_key, upper_volume, sensor_data)
            return interpolated_volume
        else:
            return None

def interpolate(x1, y1, x2, y2, x):
    interpolated_value = y1 + ((y2 - y1) / (x2 - x1)) * (x - x1)
    return round(interpolated_value, 3)


#chart





if __name__ == '__main__':
    app.run(debug=True)
