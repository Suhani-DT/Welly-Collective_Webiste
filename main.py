from flask import Flask, render_template, redirect, request
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt 
from flask import session

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "wegc1234"
DATABASE = "designer.db"

#connecting to the database
def create_connection(db_file):
  """create connection to database"""
  try:
    connection = sqlite3.connect(db_file)
    return connection
  except Error as e:
    print(e)
  return None
  
#login function
def is_logged_in():
  if session.get("email") is None:
    print("not logged in")
    return False
  else:
    print("logged in")
    return True

def is_ordering():
  if session.get("order") is None:
    print("Not ordering")
    return False
  else:
    print("Ordering")
    return True
  
def get_list(query, params):
  con = create_connection(DATABASE)
  cur = con.cursor()
  if params == "":
    cur.execute(query)
  else:
    cur.execute(query, params)
  query_list = cur.fetchall()
  con.close()
  return query_list


def put_data(query, params):
  con = create_connection(DATABASE)
  cur = con.cursor()
  print("Query:", query)
  print("Params:", params)
  try:
    cur.execute(query, params)
    con.commit()
    print("Data inserted successfully")
  except Error as e:
    print("Error occurred:", e)

  finally:
    con.close()


def summarise_order():
  print("sum ord def")
  order = session['order']
  print(order)
  order.sort()
  print(order)
  order_summary = []
  last_order = -1
  for item in order:
    if item != last_order:
      order_summary.append([item, 1])
      last_order = item
    else:
      order_summary[-1][1] += 1
  print(order_summary)
  return (order_summary)

@app.route('/')
def render_homepage():
  if 'order' not in session:
    session['order'] = []
  message = request.args.get('message')
  print(message)
  if message is None:
    message = ""
  return render_template('home.html', logged_in = is_logged_in(), message=message, ordering=is_ordering())

@app.route('/product/<int:product_id>')
def render_product_detail(product_id):
  # Fetch data using product_id
  product = get_list("SELECT * FROM products WHERE product_id=?", (product_id,))
  print("Fetched product:", product)
  if not product:
    return redirect('/products/1?error=Product+not+found')

  product = product[0]
  return render_template('product_detail.html', product=product, logged_in=is_logged_in(), ordering=is_ordering())

@app.route('/products/<cat_id>')
def render_products_page(cat_id):
  if 'order' not in session:
    session['order'] = []
  con = create_connection(DATABASE)

  #fetch all categories
  query = "SELECT * FROM category"
  cur = con.cursor()
  cur.execute(query)
  category_list = cur.fetchall()
  print(category_list)

  selected_category_name = None

  if cat_id == "0":
    #fetch all products
    cur.execute("SELECT * FROM products")
    product_list=cur.fetchall()
  else:
    #fetch selected category name
    cur.execute("SELECT name FROM category WHERE cat_id=?", (cat_id, ))
    result = cur.fetchone()
    selected_category_name = result[0] if result else None

    #fetch the products
    #make sure the name is consist across
    query = "SELECT * FROM products WHERE cat_id =? ORDER BY itemname"
    cur = con.cursor()
    cur.execute(query, (cat_id, ))
    product_list = cur.fetchall()

  con.close()


  if not product_list:
    return redirect("/products_not_found")
    #If product_list is empty, it means the cat_id doesn't match any existing category.
    #You can handle this situation and return an appropriate response, e.g., redirect to another page.
 
  print(product_list)
  return render_template('products.html', categories = category_list, products = product_list, logged_in=is_logged_in(), ordering=is_ordering(), selected_category_name=selected_category_name)


@app.route('/contact')
def render_contact_page():
    return render_template('contact.html', logged_in = is_logged_in())


#login function
@app.route('/login', methods=['GET', 'POST'])
def render_login_page():
    error = request.args.get("error", "")

    if request.method == 'POST':
        # Prevent logged-in users from submitting POST again
        if is_logged_in():
            return redirect('/?message=You+are+already+logged+in')

        # --- Your login POST logic ---
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        query = "SELECT user_id, fname, lname, email, password, role FROM user WHERE email = ?"
        con = create_connection(DATABASE)
        cur = con.cursor()
        cur.execute(query, (email,))
        user_data = cur.fetchone()
        con.close()

        if not user_data:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        user_id, first_name, last_name, db_email, db_password, user_role = user_data

        if not bcrypt.check_password_hash(db_password, password):
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # Save login info in session
        session['email'] = db_email
        session['user_id'] = user_id
        session['firstname'] = first_name
        session['role'] = user_role

        return redirect('/')

    # --- GET request ---
    # Always render login page for GET, even if logged in
    already_logged_in = is_logged_in()
    return render_template("login.html", logged_in=already_logged_in, error=error)


#logout function
@app.route('/logout')
def logout():
  print(list(session.keys()))
  [session.pop(key) for key in list(session.keys())]
  print(list(session.keys()))
  return redirect('/login?message=See+you+next+time!')


#signup function
@app.route('/signup', methods=['POST', 'GET'])
def render_signup_page():
  if is_logged_in():
    return redirect('/products/1')
  if request.method == 'POST':
    print(request.form)
    fname = request.form.get('fname').title().strip()
    lname = request.form.get('lname').title().strip()
    email = request.form.get('email').lower().strip()
    password = request.form.get('password')
    password2 = request.form.get('password2')
    role = request.form.get('role') #adding role to signup app route

    if password != password2:
      return redirect("/signup?error=Passwords+do+not+match")

    if len(password) < 8:
      return redirect("/signup?error=Password+must+be+at+least+8+characters")

    hashed_password = bcrypt.generate_password_hash(
      password).decode('utf-8')  #creating a hash password
    print(hashed_password)
    con = create_connection(DATABASE)
    query = "INSERT INTO user(fname, lname, email, password, role) VALUES(?, ?, ?, ?, ?)"
    cur = con.cursor()

    try:
      cur.execute(query, (fname, lname, email, hashed_password, role))  #this line executes the query
    except sqlite3.IntegrityError:
      con.close()
      return redirect('/signup?error=Email+is+already+used')

    con.commit()
    con.close()

    return redirect("/login")
  return render_template('signup.html', logged_in=is_logged_in())

#admin helper function
def is_admin():
  return session.get("role") == "admin"

#admin section
@app.route('/admin')
def render_admin():
  if not is_logged_in():
    return redirect('/message=Need+to+be+logged+in.')
  if not is_admin():
    return redirect('/?message=Access+Denied+Not+Admin+Account')
  con = create_connection(DATABASE)
  #fetch the categories
  query = "SELECT * FROM category"
  cur = con.cursor()
  cur.execute(query)
  category_list = cur.fetchall()

  #fetch the products
  query = "SELECT * FROM products"
  cur.execute(query)
  product_list = cur.fetchall()
  print(product_list)

  con.close()

  if not product_list:
    return render_template("admin.html", logged_in=is_logged_in(), categories=category_list, no_items=True)
  return render_template("admin.html", logged_in=is_logged_in(), categories=category_list, products=product_list)

@app.route("/delete_item_page")
def delete_item_page():
  con = create_connection(DATABASE)
  cur = con.cursor()

  # fetch categories
  cur.execute("SELECT cat_id, name FROM category")
  categories = cur.fetchall()

  # fetch products
  cur.execute("SELECT product_id, dname, itemname FROM products")
  products = cur.fetchall()
  con.close()

  return render_template("delete_item_page.html", categories=categories, products=products)


#adding a category function
@app.route('/add_category', methods = ['POST'])
def add_category():
  if not is_logged_in():
    return redirect('/message=Need+to+be+logged+in.')
  if not is_admin():
    return redirect('/?message=Access+Denied+Not+Admin+Account')
  if request.method == "POST":
    print(request.form)
    cat_name = request.form.get('name').lower().strip()
    print(cat_name)
    con = create_connection(DATABASE)
    query = "INSERT INTO category ('name') VALUES (?)"
    cur = con.cursor()
    cur.execute(query, (cat_name, ))
    con.commit()
    con.close()
  return redirect('/admin')


#deleting a category function
@app.route('/delete_category', methods = ['POST'])
def render_delete_category():
  if not is_logged_in():
    return redirect('/message=Need+to+be+logged+in.')
  if not is_admin():
    return redirect('/?message=Access+Denied+Not+Admin+Account')
  if request.method == "POST":
    con = create_connection(DATABASE)
    category = request.form.get('cat_id')
    print(category)
    category = category.split(", ")
    cat_id = category[0]
    cat_name = category[1]
    return render_template("delete_confirm.html", id=cat_id, name=cat_name, type='category')
  return redirect("/admin")

#confirmation of delete category
@app.route('/delete_category_confirm/<int:cat_id>')
def render_delete_category_confirm(cat_id):
  if not is_logged_in():
    return redirect('/message=Need+to+be+logged+in.')
  con = create_connection(DATABASE)
  query = "DELETE FROM category WHERE cat_id = ?"
  cur = con.cursor()
  cur.execute(query, (cat_id, ))
  con.commit()
  con.close()
  return redirect("/admin")

#adding an item 
#fix the products - with its details  
@app.route('/add_item', methods = ['POST'])
def render_add_item():
  if not is_logged_in():
    return redirect('/message=Need+to+be+logged+in.')
  if not is_admin():
    return redirect('/?message=Access+Denied+Not+Admin+Account')
  if request.method == "POST":
    print(request.form)
    product_id = request.form.get('product_id')
    dname = request.form.get('dname').strip()
    itemname = request.form.get('itemname').lower().strip()
    cat_id = request.form.get('cat_id').strip()
    price = request.form.get('price').strip()
    stockleft = request.form.get('stockleft').strip()
    description = request.form.get('description').strip()
    image = request.form.get('image').strip()



    print(product_id, dname, itemname, cat_id, price, stockleft, description,image)
    con = create_connection(DATABASE)
    query = "INSERT INTO products ('product_id', 'dname', 'itemname', 'cat_id', 'price', 'stockleft','description', 'image') VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    cur = con.cursor()
    cur.execute(query, (product_id, dname, itemname, cat_id, price, stockleft, description, image))
    con.commit()
    con.close()
  return redirect('/admin')


#deleting a item function
@app.route('/delete_item', methods=['POST'])
def render_delete_item():
  if not is_logged_in():
    return redirect('/message=Need+to+be+logged+in.')
  if not is_admin():
    return redirect('/?message=Access+Denied+Not+Admin+Account')

  if request.method == "POST":
    con=create_connection(DATABASE)
    products = request.form.get('item_id')
    print(products)
    if products is None:
      return redirect("/admin?error=No+item+selected")

    products = products.split(", ")
    item_id = products[0]
    item_name = products[1] if len(products) > 1 else "" #assign an empty string if item_name doesn't exist
    print(item_id, item_name)

    return render_template("delete_item_confirm.html", id=item_id, name=item_name, type='products')
  return redirect("/admin")

#confirm delete item
@app.route('/delete_item_confirm/<int:item_id>')
def render_delete_item_confirm(item_id):
  print("I am in here")
  if not is_logged_in():
    return redirect('/message=Need+to+be+logged+in.')
  if not is_admin():
    return redirect('/?message=Access+Denied+Not+Admin+Account')

  con=create_connection(DATABASE)
  query = "DELETE FROM products WHERE product_id = ?"
  cur = con.cursor()
  cur.execute(query, (item_id, ))
  con.commit()
  print("Test: ", item_id)
  con.close()  

  return redirect("/admin")

#add product to cart
@app.route('/add_to_cart/<product_id>')
def add_to_cart(product_id):
  #check to see whether product id is a valid number
  try:
    product_id = int(product_id)
  except ValueError:
    print("{} is not an integer".format(product_id))
    return redirect("/products/1?error=Invalid+product+id")

  #add the product to the cart
  #no check is made at this stage to see if it is a valid product

  print("Adding product to cart", product_id)
  order = session['order']
  print("Order before adding", order)
  order.append(product_id)
  print("Order after adding", order)
  session['order'] = order
  #return to the page the link was pressed from
  return redirect(request.referrer)


#cart function
@app.route('/cart', methods=['POST', 'GET'])
def render_cart():
  if request.method == "POST":
    name = request.form['name']
    print(name)
    put_data("INSERT INTO orders VALUES (null, ?, TIME('now'), ?)", (name, 1))
    order_number = get_list("SELECT max(order_id) FROM orders WHERE name = ?",
                            (name, ))
    print(order_number)
    order_number = order_number[0][0]
    orders = summarise_order()
    print("Orders:", orders)
    #session['message'] = f"Order has been placed under the name {name}"
    #return redirect('/')

    for order in orders:
      put_data("INSERT INTO order_content VALUES (null, ?, ?, ?)",
               (order_number, order[0], order[1]))
    session['message'] = f"Order has been placed under the name {name}"
    print("Session message:", session['message'])
    session.pop('order')
    return redirect(f'/?message=Order+has+been+placed+under+the+name+{name}')

  else:
    orders = summarise_order()
    total = 0
    for item in orders:
      item_detail = get_list("SELECT itemname, price FROM products WHERE product_id = ?",
                             (item[0], ))
      print(item_detail)
      if item_detail:
        item.append(item_detail[0][0])
        item.append(item_detail[0][1])
        item.append(item_detail[0][1] * item[1])
        total += item_detail[0][1] * item[1]
    print("Orders:", orders)
    return render_template("cart.html",
                           logged_in=is_logged_in(),
                           ordering=is_ordering(),
                           products=orders,
                           total=total)


#cancel order function
@app.route('/cancel_order')
def cancel_order():
  session.pop('order')
  return redirect('/?message=Cart+Cleared.')

'''@app.route('/orders/<processed>')
def render_processed_orders(processed):
  label = "processed"
  if processed == "1":
    label = "un" + label
  #get the list of orders
  processed = int(processed)
  # Whats does this mean
  all_orders = get_list("SELECT order.id, order.name, order.timestamp, products.itemname, order_content.quantity, products.price FROM orders"
                     " INNER JOIN order_content ON orders.id=order_content.order_id"
                     " INNER JOIN products ON order_content.product_id=products.id"
                     " INNER JOIN category ON products.cat_id = category.id"
                     " WHERE orders.processed=?", (processed, ))
  print(all_orders)
  orders = []
  last_id = -1
  for order in all_orders:
    if order[0] != last_id:
      orders.append([])
      orders[-1] = [order[0], order[1], order[2], [], 0]
      last_id = order[0]
      orders[-1][3].append([order[3], order[4], order[5], order[4] * order[5]])
      orders[-1][4] += order[4] * order[5]
    print(orders)

  return render_template('orders.html', orders=orders, label=label, logged_in=is_logged_in())'''

#process order with order id
#@app.route('/process_orders/<order_id>', methods=['POST'])
#def process_order(order_id):
'''if not is_admin():
    return redirect('/?message=Access+Denied+Not+Admin+Account')
  if request.method == 'POST':
    print("updating order process function")
    #set the processed flag to 0 to mark it as processed
    put_data("UPDATE orders SET processed=0 WHERE order_id=?", (order_id, ))
    print("Order processed:", order_id)
    return redirect(request.referrer)'''

if __name__ == "__main__":
  app.run(host='0.0.0.0', port=81, debug=True)
