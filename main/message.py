# Database imports
import numpy as np
from tabulate import tabulate
import pandas as pd
from pandasql import sqldf
from datetime import datetime
import hashlib
# Flask imports
import re
from flask import Flask, render_template, request, redirect, url_for, make_response

pd.set_option('display.max_colwidth', None) 
pd.set_option('display.max_rows', None) 
driver_columns_keys = ['DLN', 'Fname', 'Lname', 'State', 'Address']
car_columns_keys = ['VIN', 'Model', 'Make' ,'Year', 'Color','Owner_fname', 'Owner_lname' 'Owner DLN']
driver_account = ['Login', 'Password', 'Token', 'DLN', 'Fname', 'Lname']
employee_account = ['Login', 'Password', 'Token']

df_car_history = pd.DataFrame(columns=['VIN', 'From', 'To', 'Date'])
df_driver_columns_keys = pd.DataFrame(columns=driver_columns_keys)
df_car_columns_keys = pd.DataFrame(columns=car_columns_keys)
df_driver_account = pd.DataFrame(columns=driver_account)
df_employee_account = pd.DataFrame(columns=employee_account)

def hash_password(password_string):
    hasher =  hashlib.sha256()
    hasher.update(password_string.encode('utf-8'))
    hex_string = hasher.hexdigest()
    return hex_string

def create_new_account(login_type, login, password, info=[]):
    password = hash_password(password)
    token = hash_password(login+password)
    if login_type=="e":
        df_employee_account.loc[len(df_employee_account.index)] = [login, password, token] 
    else:
        df_driver_account.loc[len(df_driver_account.index)] = [login, password, token] + info

def create_new_car_record(login_type, token, car_record):
    if login_type=="e" and token in df_employee_account["Token"].values:
        df_car_columns_keys.loc[len(df_car_columns_keys.index)] = car_record
    elif (token in df_driver_account["Token"].values):
        df_car_columns_keys.loc[len(df_car_columns_keys.index)] = car_record
    else:
        return "Error"
    
def update_car_record(login_type, token, car_record):
    if login_type=="e" and token in df_employee_account["Token"].values:
        df_car_columns_keys.loc[len(df_car_columns_keys.index)] = car_record
    else:
        return "Error"

def upload_driver_info(login_type, token, new_driver_info):
    if login_type == "d" and token in df_driver_account["Token"].values:
        df_driver_account.loc[df_driver_account.loc[df_driver_account['Token'] == token].index[0]]=new_driver_info
    else:
        return "Error"

def view_info(login_type, token):
    if login_type == "d" and token in df_driver_account["Token"].values:
        drivers_dln = df_driver_account.loc[df_driver_account.loc[df_driver_account['Token'] == token].index[0]]["DLN"]
        return df_car_columns_keys.loc[df_car_columns_keys['Owner DLN'] == drivers_dln]
    else:
        return "Error"

create_new_account("e","mama","mama")
df_employee_account

# Flask code
app = Flask(__name__)

# Load existing databases
drivers_df = pd.read_csv("dummy_car_data.csv")  
cars_df = pd.read_csv("dummy_driver_data.csv")  

@app.route('/getToken', methods = ['POST', 'GET'])
def get_token(login, password):
    password = hash_password(password)
    token = hash_password(login+password)
    return token

@app.route('/setCookie', methods = ['POST', 'GET'])
def setCookie():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
    cookieValue = get_token(username, password) # Create cookie value
    response = make_response(render_template('index.html')) # Create a response
    response.set_cookie('ID', cookieValue) #Set cookie value
    return response
           
@app.route('/getCookie', methods = ['POST', 'GET'])
def getCookie():
    cookieValue = request.cookies.get('ID')
    return cookieValue

# Routes
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashedPass = hash_password(password)
        # Check for existing username and password
        if username in df_employee_account["Login"].values and hashedPass in df_employee_account["Password"].values:
            # Employee login
            return render_template('employee.html')
        elif username in df_driver_account["Login"].values and hashedPass in df_driver_account["Password"].values:
            # Driver login
            return render_template('user_page.html')
        else:
            return "Incorrect login information"
    return render_template('index.html')

# register a new account
@app.route('/register', methods=['GET', 'POST']) #not sure if registration would require the use of GET function
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        DLN = request.form['DLN']
        address = request.form['address']
        name = request.form['Name']
        
        print(username)
        print(password)
        # Check for existing username and password
        hashedPass = hash_password(password)
        if username in df_employee_account["Login"].values and hashedPass in df_employee_account["Password"].values:
            return "Account cannot be created."
        elif username in df_driver_account["Login"].values and hashedPass in df_driver_account["Password"].values:
            return "Account cannot be created."
        else:
            login_type = "d" # Employee logins are predetermined
            name = username
            passwd = password
            create_new_account(login_type, name, passwd,[DLN,address,name])
            print("Account has been successfully created!")
            return redirect(url_for('user_page'))
    return render_template('register.html')
		
# All information for the user page will be retrieved in this app route
@app.route('/user_page', methods=['GET','POST'])
def user_page():
    # Get user-specific data from the database
    return render_template('user_page.html', dynamic_text="Template")

def upload_driver_info_user_page():
    if request.method == 'POST':
        driver = {
            'Fname' : request.form['fname'],
            'Lname' : request.form['lname'],
            'DLN' : request.form['DLN'],
            'Address' : request.form['Address'],
        }
        if driver.DLN not in df_driver_columns_keys["DLN"].values and driver.Address not in df_driver_columns_keys["Address"]:
            new_driver_info = driver.Fname + driver.Lname + driver.DLN + driver.Address
            upload_driver_info("d", getCookie(), new_driver_info)
    return render_template('upload_driver_info.html', username=username)

# Register a New Car
def register_new_car(username):
    if request.method == 'POST':
        car = {
            'VIN' : request.form['VIN'],
            'Make' : request.form['Make'],
            'Model' : request.form['Model'],
            'Color' : request.form['Color'],
            'Owner_First_Name' : request.form['Owner_First_Name'],
            'Owner_Last_Name' : request.form['Owner_Last_Name'],
            'Owner_License_Number' : request.form['Owner_License_Number'],      
        }
        if car.VIN not in df_car_columns_keys["VIN"].values: # Car is not found in database
           cars_df.loc[len(cars_df)] = car # Add new car
           cars_df.to_csv("cars.csv", index=False)  # Save the DataFrame to a CSV file
           return redirect(url_for('user_page', username=username))
        else:
           return "Car is already registered!"
    return render_template('user_page.html', username=username)

# Transfer Car Information
def transfer_car_info():
    if request.method == 'POST':
        carToTransfer = {
            'transferVin' : request.form['transferVIN']
        }
        new_owner = {
            'New_fname' : request.form['New_fname'],
            'New_lname' : request.form['New_lname'],
            'New_Address' : request.form['New_Address'],
            'New_DLN' : request.form['New_DLN'],
        }
        # Transfer logic
        if new_owner.New_fname in df_driver_columns_keys["fname"] and new_owner.New_lname in df_driver_columns_keys["lname"] and new_owner.New_Address in df_driver_columns_keys["Address"] and new_owner.New_DLN in df_driver_column_key["DLN"]: # Driver exists
           if carToTransfer.transferVIN in df_car_columns_keys["VIN"]:
                tempdf = {'VIN' : carToTransfer.transferVIN}
        # I'm not sure if the next two lines are needed but I'll keep it here in case someone thinks otherwise
        cars_df.to_csv("cars.csv", index=False)  # Save the DataFrame to a CSV file
        return redirect(url_for('user_page', username=username))
    return render_template('user_page.html', username=username)

# View Info
def view_info(username):
    if request.method == 'POST':
           info = view_info("d", getCookie())
           return info
        # I'm not sure if the next line is needed but I'll keep it here in case someone thinks otherwise
    user_cars = cars_df[cars_df['username'] == username][['Owner_First_Name', 'Owner_First_Name', 'Owner_License_Number', 'VIN']]
    return render_template('user_page.html', username=username, drivers=user_drivers, cars=user_cars)

# Example function for querying the database using pandasql with input validation and sanitation
def query_database(query):
    clean_query = sanitize_input(query)
    result = sqldf(clean_query, globals()) # The qeury is executed in a global scope and not a local one
    return result.to_dict(orient='records') # Converts the dataframe into a dictionary and saves it in a list-like (records) style

def sanitize_input(query):
    # Numbers should not be replaced since the car VIN needs numbers as the input. I'm not sure if there's a way to sanitize the query based on what is being inputted by the user, so this function might need to be modified.
    clean_query = re.sub(r'-#!@$%&*"\\\./`~=;[^a-zA-Z\s\c]', '', query) # Replaces the characters in the first section with the ones in the second section (which is empty)
    return clean_query

@app.route('/query_page', methods=['GET', 'POST'])
def query_page():
    if request.method == 'POST':
        user_query = request.form['user_query'] # Takes the user query and adds it to the variable user_query
        clean_user_query = sanitize_input(user_query) # Sanitizes query
        result = query_database(clean_user_query) # Queries the database
        return render_template('query_result.html', result=result) # Returns the new HTML page containing the query_result
    return render_template('employee.html') # If the query isn't accepted, the employee page will show up (it will refresh)

if __name__ == '__main__':
    app.run(debug=True)