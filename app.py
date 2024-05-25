from flask import Flask, request,render_template, redirect,session,url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import logging
import json
from sqlalchemy import or_
from sqlalchemy import desc


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'
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




class LevelSensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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



@app.route('/dashboard', defaults={'page': 1})
@app.route('/dashboard/page/<int:page>')
def dashboard(page):
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()

        # Check if filter is provided in the request
        filter_by = request.args.get('filter')
        
        # Set default ordering if no filter is provided
        order_by = LevelSensorData.id.desc()  # Default ordering by ID descending
        
        # Update ordering based on filter value
        if filter_by == 'asc':
            order_by = LevelSensorData.id.asc()  # Ascending order by ID
        
        per_page = 10  # Number of entries per page
        level_sensor_query = LevelSensorData.query.order_by(order_by).paginate(page, per_page, False)

        total_pages = level_sensor_query.pages
        sense_data = level_sensor_query.items

       
        sensor_data_count = LevelSensorData.query.count()
        imei_count = db.session.query(LevelSensorData.imei).distinct().count()

        return render_template('dashboard.html', user=user,sense_data=sense_data, sensor_data_count=sensor_data_count, imei_count=imei_count,
                               page=page, total_pages=total_pages)
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
            new_data = LevelSensorData(date=date, full_addr=full_addr, sensor_data=sensor_data, imei=imei)
            db.session.add(new_data)
            db.session.commit()

            # Log success
            logging.info("Data stored successfully: %s", sense_data)

            # Return a response
            response = {'status': 'success', 'message': 'Data received and stored successfully'}
            return jsonify(response), 200

        except Exception as e:
            # Log failure
            logging.error("Failed to store data: %s", e)
            return jsonify({'status': 'failure', 'message': 'Failed to store data'}), 500

    logging.info("Received non-POST request at /level_sensor_data, redirecting to /dashboard")
    return redirect('/dashboard')
    

# api for count dashboard blobs 

@app.route('/api/sensor_data_count', methods=['GET'])
def get_sensor_data_count():
    try:
        count = LevelSensorData.query.count()
        return jsonify({"sensor_data_count": count}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500


@app.route('/api/imei_count', methods=['GET'])
def get_imei_count():
    try:
        imei_count = db.session.query(LevelSensorData.imei).distinct().count()
        return jsonify({"imei_count": imei_count}), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500




    #search for table 
@app.route('/search_sensor_data', methods=['GET'])
def search_sensor_data():
    search_query = request.args.get('query')
    search_results = LevelSensorData.query.filter(
        db.or_(
            LevelSensorData.id.like(f'%{search_query}%'),
            LevelSensorData.date.like(f'%{search_query}%'),
            LevelSensorData.full_addr.like(f'%{search_query}%'),
            LevelSensorData.sensor_data.like(f'%{search_query}%'),
            LevelSensorData.imei.like(f'%{search_query}%')
        )
    ).all()
    results_list = []
    for entry in search_results:
        results_list.append({
            'id': entry.id,
            'date': entry.date,
            'full_addr': entry.full_addr,
            'sensor_data': entry.sensor_data,
            'imei': entry.imei
        })
    return jsonify(results_list)

if __name__ == '__main__':
    app.run(debug=True)
