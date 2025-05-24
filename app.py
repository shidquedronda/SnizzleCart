from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import mysql.connector
import bcrypt
import json
import os
import razorpay
import random
import hashlib
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta
import uuid
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'pokimon12'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = False  # Set to True if you're using HTTPS


# ---------------------- Flask-Login Setup ----------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in first"
login_manager.login_message_category = "warning"  # Bootstrap class: alert-warning

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM accounts WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        return User(user['id'], user['username'])
    return None

# ---------------------- DB Connection ----------------------
import os

def get_db_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASS"),
        database=os.environ.get("DB_NAME"),
        port=int(os.environ.get("DB_PORT", 3306))
    )

# ---------------------- Routes ----------------------


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usernam = request.form['username']
        pan = usernam
        password = request.form['password'].encode('utf-8')
        remember = 'remember' in request.form

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM accounts WHERE username = %s", (usernam,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            user_obj = User(user['id'], user['username'])
            login_user(user_obj, remember=remember)
            session['user'] = {
            'username': pan,
            'theme': 'dark'
            }
            print(session['user']['username'])
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials. Please try again.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()          # Clears user login AND removes remember_token cookie
    session.clear()        # Clears session data manually stored
    resp = redirect(url_for('login'))

    # Explicitly clear 'remember_token' cookie from browser (just in case)
    resp.set_cookie('remember_token', '', expires=0)
    flash("Logout successful.", "success")
    return resp



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        global uname
        username = request.form.get('username')
        uname = username
        password = request.form.get('password').encode('utf-8')
        name = request.form.get('name')
        address = request.form.get('Address')
        phoneg = request.form.get('PNumber')
        p_no = '91'+ phoneg
        print(p_no)

        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO accounts (username, password, name, address, phoneN) "
                "VALUES (%s, %s, %s, %s, %s)",
                (username, hashed_pw.decode('utf-8'), name, address,p_no)
            )
            conn.commit()
            cursor.close()
            conn.close()
            flash("Please add profile", "success")
            session['profile']={
                'username':username,
                'name':name,
                'phoneN':p_no,
                'address':address
            }
            return redirect(url_for('add_profile'))
        except mysql.connector.IntegrityError:
            flash("Username already exists. Please try a different one.", "warning")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/search')
def search():
    query = request.args.get('q', '').strip().lower()
    results = []

    json_path = os.path.join(app.static_folder, 'data', 'products.json')
    with open(json_path, 'r') as f:
        data = json.load(f)

    all_products = []
    for cat, items in data.items():
        for p in items:
            p['category'] = cat
            all_products.append(p)

    if query:
        results = [p for p in all_products if query in p['name'].lower()]

    return render_template('search.html', results=results, query=query)

#----------------------Success---------------------------------------

@app.route("/success")
def success():
    user_id = session['user']['username']
    if not user_id:
        return redirect(url_for('login'))

    # Get the most recent order for the logged-in user
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM orders WHERE username = %s ORDER BY created_at DESC LIMIT 1", (user_id,))
    order = cursor.fetchone()
    cursor.close()

    return render_template("success.html", order=order)



#----------------------------orderPlacing---------------------------


@app.route("/submit-order", methods=["POST"])
def submit_order():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    cart = data.get("cart", [])
    address = data.get("address")
    pincode = data.get("pincode")
    delivery_date = data.get("delivery_date")
    payment_method = data.get("payment_method")
    payment_id = data.get("payment_id", None)

    total = sum(item['price'] * item.get('quantity', 1) for item in cart)

    if not cart or not address or not pincode or not delivery_date or not payment_method:
        return jsonify({"error": "Missing fields"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
          
        # Insert order into orders table (no 'total' column)
        status = 'Ordered'
        order_id = random.randint(100, 1000)
        cursor.execute("""
                       INSERT INTO orders (order_id, username, total, address, pincode, delivery_date, payment_method, payment_id, status)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                       """, (order_id, session['user']['username'], total, address, pincode, delivery_date, payment_method, payment_id, status)) 



        # Insert cart items into order_items
        for item in cart:
            imagefor = '/static/' + item['image']
            p_id = item['p_id']
            cursor.execute("""
                INSERT INTO order_items (order_id, product_name, price, quantity, image, p_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                order_id, item['name'], item['price'], item.get('quantity', 1), imagefor, p_id
            ))
            conn.commit()

    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": str(e)}), 500

    cursor.close()
    conn.close()

    return jsonify({"success": True, "order_id": order_id})


#------------------------------View_order-------------------------
@app.route('/view_orders')
def view_orders():
    if 'user' not in session or not session['user'].get('username'):
        return redirect('/login')

    username = session['user']['username']
    conn = get_db_connection()

    cursor1 = conn.cursor(dictionary=True, buffered=True)

    # Fetch all order_ids for the user
    cursor1.execute("SELECT order_id FROM orders WHERE username = %s", (username,))
    orders = cursor1.fetchall()
    cursor1.close()

    if not orders:
        conn.close()
        return render_template('view_order.html', orders=[])

    cursor2 = conn.cursor(dictionary=True, buffered=True)

    all_orders = []

    for order in orders:
        order_id = order['order_id']
        
        # Get details for each order
        cursor2.execute("""
            SELECT orders.order_id, orders.delivery_date, orders.status, 
                   order_items.product_name, order_items.quantity, order_items.price, order_items.image, order_items.p_id
            FROM orders
            JOIN order_items ON orders.order_id = order_items.order_id
            WHERE orders.order_id = %s
        """, (order_id,))
        
        order_details = cursor2.fetchall()
        all_orders.append({
            'order_id': order_id,
            'items': order_details,
            'delivery_date': order_details[0]['delivery_date'] if order_details else None,
            'status': order_details[0]['status'] if order_details else 'Unknown'
        })

    cursor2.close()
    conn.close()
    print(all_orders)

    return render_template('view_order.html', orders=all_orders)





@app.route('/product')
def product():
    name = request.args.get('name', '')
    product = None

    json_path = os.path.join(app.static_folder, 'data', 'products.json')
    with open(json_path, 'r') as f:
        data = json.load(f)

    for items in data.values():
        for p in items:
            if p['name'] == name:
                product = p
                break
        if product:
            break

    if not product:
        flash(f"Product “{name}” not found.", "warning")
        return redirect(url_for('index'))

    return render_template('product.html', product=product)

razorpay_client = razorpay.Client(auth=("rzp_test_DpgHww99csrn1x", "Mx29YQwCk2XvIfy5o8kc2iZr"))

@app.route('/create-order', methods=['POST'])
def create_order():
    data = request.get_json()
    amount = int(data['amount'] * 100)
    payment = razorpay_client.order.create({
        "amount": amount,
        "currency": "INR",
        "payment_capture": 1
    })



    return jsonify(payment)


@app.route('/cart')
@login_required
def cart():
    return render_template('cart.html')

@app.route('/checkout')
@login_required
def checkout():
    return render_template('checkout.html')

@app.route('/landing')
def landing():
    return render_template('Landing Page.html')

@app.route('/')
@login_required
def home():
    print("User ID from current_user:", current_user.get_id())
    return render_template('index.html')


@app.route('/setting')
@login_required
def setting():
    return render_template('setting.html')

@app.route('/api/cookies')
def get_cookies():
    if 'user' not in session:
        return jsonify([])  # Empty list or object when no session

    poto = load_profile_json_file(PROFILE_FILE)

    for i in poto:
        if i['username'] == session['user']['username']:
            return jsonify([{
                'name': i['name'],
                'image': i['image']
            }])
    return jsonify([])

    

# ---------------------- Product Add (Admin) ----------------------
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
PRODUCTS_FILE = os.path.join(app.static_folder, 'data', 'products.json')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_json_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def load_json_file(path):
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        return {}
    with open(path, 'r') as f:
        return json.load(f)

def save_to_database(p_id, name, price, date):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            INSERT INTO product (P_ID, P_name, Price, Listing_date)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (p_id, name, price, date))
        conn.commit()
    except mysql.connector.Error as err:
        print(f"❌ Error saving to database: {err}")
    finally:
        cursor.close()
        conn.close()

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():

    if not session.get('admin_logged_in'):
        flash('⚠️ Please log in as admin first.', 'danger')
        return redirect(url_for('admin_login'))
    
    if request.method == 'POST':
        category = request.form['category'].strip().title()
        name = request.form['name'].strip()
        price = float(request.form['price'])
        brand = request.form['brand'].strip()
        listing_date = request.form['listing_date']
        description = request.form['description'].strip()

        if 'images' not in request.files:
            return "❌ No images part in form", 400

        files = request.files.getlist('images')
        image_paths = []

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                file.save(save_path)
                relative_path = os.path.relpath(save_path, app.static_folder).replace('\\', '/')
                image_paths.append(relative_path)


        if not image_paths:
            return "❌ At least one valid image is required.", 400

        main_image = image_paths[0]
        product_id = random.randint(100, 1000)

        product = {
            "p_id": product_id,
            "name": name,
            "brand": brand,
            "price": price,
            "image": main_image,
            "images": image_paths,
            "description": description
        }

        data = load_json_file(PRODUCTS_FILE)
        if category not in data:
            data[category] = []
        data[category].append(product)
        save_json_file(PRODUCTS_FILE, data)

        save_to_database(product_id, name, price, listing_date)
        flash('Product added successfully', 'success')

        return redirect(url_for('admin_dashboard'))

    return render_template('add_product.html')

# ---------------------- Profile Upload Setup ----------------------
app.config['PROFILE_UPLOAD_FOLDER'] = 'static/profile_img'
PROFILE_FILE = os.path.join(app.static_folder, 'data', 'profile.json')

def allowed_profile_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_profile_json_file(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def load_profile_json_file(path):
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        return []
    with open(path, 'r') as f:
        return json.load(f)

# ---------------------- Profile Route ----------------------
@app.route('/add_profile', methods=['GET', 'POST'])
def add_profile():
    if 'profile' not in session:
        flash('please signup first', 'warning')
        return render_template('register.html')
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT name, address, phoneN FROM accounts WHERE username = %s", (uname,))
            result = cursor.fetchone()
            if not result:
                return "❌ User not found in database.", 404
            name, address, phoneN = result
        except mysql.connector.Error as err:
            return f"❌ Database error: {err}", 500
        finally:
            cursor.close()
            conn.close()

        # Image upload handling
        if 'images' not in request.files:
            flash("No image found", "warning")
            return redirect(url_for('add_profile'))

        files = request.files.getlist('images')
        image_paths = []

        for file in files:
            if file and allowed_profile_file(file.filename):
                filename = secure_filename(file.filename)
                save_path = os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], filename)
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                file.save(save_path)
                image_paths.append('/' + save_path.replace('\\', '/'))

        if not image_paths:
            flash("Upload Valid Image", "warning")
            return redirect(url_for('add_profile'))

        main_image = image_paths[0]

        profile = {
            "username": uname,
            "name": name,
            "phoneN": phoneN,
            "image": main_image,
            "address": address
        }

        session.pop('profile',None)


        data = load_profile_json_file(PROFILE_FILE)
        data.append(profile)
        save_profile_json_file(PROFILE_FILE, data)
        flash("Registration Sucessful please login", "success")

        return redirect(url_for('login'))

    return render_template('add_profile.html')

#-------------------edit_profile----------------------------

app.config['edit_UPLOAD_FOLDER'] = 'static/profile_img'
USER_DATA_FILE = os.path.join(app.static_folder, 'data', 'profile.json')


def load_user_data():
    with open(USER_DATA_FILE, 'r') as f:
        return json.load(f)


def save_user_data(data):
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    user_data = load_user_data()

    # Validate user data format
    if not user_data or not isinstance(user_data, list):
        return "User data format error", 500

    current_username = session.get('user', {}).get('username')
    print(current_username)
    if not current_username:
        return "User not logged in", 401

    for user in user_data:
        if user.get('username') == current_username:
            if request.method == 'POST':
                new_name = request.form.get('name')
                image = request.files.get('profilePic')

                # Update name
                if new_name:
                    user['name'] = new_name
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("UPDATE accounts SET name = %s WHERE username = %s", (new_name, current_username))
                    conn.commit()
                    cursor.close()
                    conn.close()


                # Update image
                if image and image.filename != '':
                    # Delete old image if exists
                    old_img_path = user.get('image')
                    if old_img_path and os.path.exists(old_img_path) and 'default.jpg' not in old_img_path:
                        os.remove(old_img_path)

                    # Save new image with a unique name
                    filename = secure_filename(image.filename)
                    unique_filename = f"{uuid.uuid4().hex}_{filename}"
                    filepath = os.path.join(app.config['edit_UPLOAD_FOLDER'], unique_filename)
                    image.save(filepath)

                    # Save relative path to user data
                    user['image'] = filepath.replace("\\", "/")

                save_user_data(user_data)
                return redirect(url_for('edit_profile'))

            # Ensure 'image' key exists for GET
            if 'image' not in user or not user['image']:
                user['image'] = 'static/profile_img/default.jpg'

            return render_template("profile.html", i=user)

    return "User not found", 404

#-------------------------Admin_authentication-----------------

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT pass FROM admin WHERE username=%s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password,user[0].encode('utf-8')):
            session['admin_logged_in'] = True
            flash('login sucessful', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('invalid cridentials', 'danger')
            return redirect(url_for('admin_login')) 
    return render_template('login_admin.html')

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():

    if not session.get('admin_logged_in'):
        flash('⚠️ Please log in as admin first.', 'danger')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
    
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')

          # Hash the password
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO admin (username, pass ) VALUES (%s, %s)", (username, hashed_pw.decode('utf-8')))
            conn.commit()
            cursor.close()
            conn.close()
            flash("Registration Sucessful please login to admin", "success")
            return redirect(url_for('admin_login'))
        except mysql.connector.IntegrityError:
            return "<h3>Username already exists. <a href='/register'>Try again</a></h3>"

    return render_template('register_admin.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash('⚠️ Please log in as admin first.', 'danger')
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('✅ Logged out successfully.', 'success')
    return redirect(url_for('admin_login'))


@app.route('/admin_view_order')
def admin_view_order():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT 
            orders.order_id, 
            orders.delivery_date, 
            orders.status, 
            orders.address,
            orders.pincode,
            order_items.price AS price, 
            order_items.p_id AS product_id
        FROM orders
        JOIN order_items ON orders.order_id = order_items.order_id
    """)
    data = cursor.fetchall()
    conn.close()

    # Group by order_id
    grouped_orders = defaultdict(lambda: {'products': []})
    for row in data:
        order_id = row['order_id']
        grouped_orders[order_id]['order_id'] = order_id
        grouped_orders[order_id]['delivery_date'] = row['delivery_date']
        grouped_orders[order_id]['status'] = row['status']
        grouped_orders[order_id]['address'] = row['address']
        grouped_orders[order_id]['price'] = row['price']
        grouped_orders[order_id]['pincode'] = row['pincode']
        grouped_orders[order_id]['products'].append({
            'product_id': row['product_id'],
            'price': row['price']
        })

    return render_template('view_order_admin.html', orders=grouped_orders.values())



@app.route('/admin/update-order-status', methods=['POST'])
def update_order_status():
    order_id = request.form['order_id']
    new_status = request.form['status']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = %s WHERE order_id = %s", (new_status, order_id))
    conn.commit()
    conn.close()
    return redirect('/admin_view_order')


#-----------------------forgot_password------------------------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    message = ''
    success = False
    verified = False
    username = ''

    if request.method == 'POST':
        step = request.form['step']

        if step == 'verify':
            username = request.form['username']
            phone = request.form['phone']
            conn = get_db_connection()

            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM accounts WHERE username = %s AND phoneN = %s", (username, phone))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            if user:
                verified = True
                success = "Phone number verified. Please enter a new password."
            else:
                message = "Invalid username or phone number."
        
        elif step == 'reset':
            username = request.form['username']
            new_password = request.form['new_password']

            # Hash the password using bcrypt
            hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE accounts SET password = %s WHERE username = %s", (hashed_pw, username))
            conn.commit()
            cursor.close()
            conn.close()

            flash('Password changed successfully. Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('forgot_password.html', message=message, success=success, verified=verified, username=username)

# ========== UPDATE INFO ROUTE ==========
@app.route('/update', methods=['GET', 'POST'])
def update():
    if 'user' not in session:
        flash('Login first', 'danger')
        return redirect(url_for('login'))

    section = request.args.get('section')
    user_id = session['user']['username']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT phoneN, address FROM accounts WHERE username = %s", (user_id,))
    result = cursor.fetchone()
    phoneN = result[0] if result else ''
    address = result[1] if result else ''

    profile_json_load = load_user_data()

    if request.method == 'POST':
        updated = False

        if section == 'phone':
            new_phone = request.form.get('phoneN')
            if new_phone:
                # Update in JSON
                for user_inf in profile_json_load:
                    if user_inf.get('username') == user_id:
                        user_inf['phoneN'] = new_phone
                        break
                # Update in DB
                cursor.execute("UPDATE accounts SET phoneN = %s WHERE username = %s", (new_phone, user_id))
                updated = True
                flash("Phone number updated successfully.", "success")

        elif section == 'address':
            new_address = request.form.get('address')
            if new_address:
                # Update in JSON
                for user_inf in profile_json_load:
                    if user_inf.get('username') == user_id:
                        user_inf['address'] = new_address
                        break
                # Update in DB
                cursor.execute("UPDATE accounts SET address = %s WHERE username = %s", (new_address, user_id))
                updated = True
                flash("Address updated successfully.", "success")

        if updated:
            conn.commit()
            save_user_data(profile_json_load)
            return redirect(url_for('update', section=section))

    cursor.close()
    conn.close()

    return render_template('updates.html', section=section, phoneN=phoneN, address=address)


#-----------------------contact_page--------------------------------------
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        # Here you can handle the message: save to DB, send email, etc.
        print(f"New message from {name} ({email}): {message}")
        
        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')


# ========== CHANGE PASSWORD ROUTE ==========
@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user' not in session:
        flash('Login First.', 'danger')
        return redirect(url_for('login'))

    current = request.form.get('current_password')
    new = request.form.get('new_password')
    confirm = request.form.get('confirm_password')

    if new != confirm:
        flash("New passwords do not match.", "danger")
        return redirect(url_for('update', section='password'))

    user_id = session['user']['username']
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get current hashed password from database
    cursor.execute("SELECT password FROM accounts WHERE username = %s", (user_id,))
    result = cursor.fetchone()

    if not result:
        flash("User not found.", "warning")
        return redirect(url_for('update', section='password'))

    stored_password = result[0]

    if not check_password_hash(stored_password, current):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for('update', section='password'))

    # Update to new hashed password
    new_hashed = generate_password_hash(new)
    cursor.execute("UPDATE accounts SET password = %s WHERE username = %s", (new_hashed, user_id))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Password changed successfully.", "success")
    return redirect(url_for('update', section='password'))

#-----------------------remove_product---------------------------------------

@app.route('/remove_product_view', methods=['GET'])

def remove_product_view():
    if not session.get('admin_logged_in'):
        flash('⚠️ Please log in as admin first.', 'danger')
        return redirect(url_for('admin_login'))
    data = load_json_file(PRODUCTS_FILE)
    return render_template('remove_product.html', all_products=data)


@app.route('/remove_product/<int:p_id>', methods=['DELETE'])
def remove_product(p_id):  # Use lowercase param name
    if not session.get('admin_logged_in'):
        flash('⚠️ Please log in as admin first.', 'danger')
        return redirect(url_for('admin_login'))
    data = load_json_file(PRODUCTS_FILE)
    found = False

    for category in list(data.keys()):
        updated_products = [p for p in data[category] if p.get("p_id") != p_id]
        if len(updated_products) != len(data[category]):
            data[category] = updated_products
            found = True
        if not data[category]:
            del data[category]

    if not found:
        return jsonify({"error": "Product not found"}), 404

    save_json_file(PRODUCTS_FILE, data)

    # Remove from database
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM product WHERE P_ID = %s", (p_id,))
        conn.commit()
    except Exception as e:
        print(f"❌ DB Error: {e}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({"success": True}), 200


#######---------------Category_route--------------------#########

@app.route('/category')
def category():
    return render_template('category.html')




if __name__ == '__main__':
    app.run(debug=True)



 
