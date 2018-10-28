from postit import databasecontroller
from postit.EventLog import EventLog
from flask import (Flask, request, jsonify, send_from_directory)
from datetime import datetime
from flask_cors import CORS
from postit.PostitHTTPError import PostitHTTPError
import configparser
import os.path
import logging
from werkzeug.utils import secure_filename

from postit.databasecontroller.SQLITEDatabaseController import DuplicateIDException, InvalidUserType

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/config.ini')
db = databasecontroller.get_database(config['database']['database_type'])
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                           config['files']['upload_folder'])
app.config['MAX_CONTENT_LENGTH'] = int(config['files']['max_size'])
CORS(app)
event_log = EventLog()


@app.route('/')
def hello_world():
    return 'Server is up'


@app.route('/info', methods=['GET', 'POST', 'PUT'])
def site_info():
    if request.method == 'GET':
        return jsonify({"response": "It worked!"})
    raise get_error_response(400, "Only GET requests are valid for this address")


@app.route('/signin', methods=['GET', 'POST', 'PUT'])
def login():
    log_request(request)
    # Use a PUT request to send login authentication data
    if request.method == 'PUT':
        logging.debug("Working PUT request in /signin")
        # Verify request data
        json_data = request.get_json()
        assert_json_data_contains(['username', 'password'], json_data, "/signin", "PUT")
        username = json_data.get('username')
        password = json_data.get('password')
        # Attempt to retrieve the account data from the database
        user_id, auth_token, last_login, password_expire_date = db.get_login_data(username, password)
        if (user_id is None) or (auth_token is None) or (password_expire_date is None):
            raise get_error_response(401, "The username/password is invalid.")
        # Check if the password has expired
        passwd_time_remaining = password_expire_date - datetime.today()
        if passwd_time_remaining.days < 0:
            event_log.write(user_id, "Attempted to log in. Password is expired.")
            raise get_error_response(401, "Your password has expired, please contact an administrator")
        # Check if the user account is active
        user_type = db.get_user_type(user_id)
        logging.debug("account_type extracted in /signin")
        if user_type == "deactivated" or user_type == "new":
            event_log.write(user_id, "Attempted to log in. Account type is " + user_type + ".")
            raise get_error_response(401, "This user account is not active. Please contact an administrator.")
        # Login is successful
        logging.debug("Account type is valid in /signin")
        event_log.write(user_id, "Logged in.")
        # Update the last login date in the database
        db.update_last_login(user_id, datetime.today())
        # Return the success response
        response = jsonify(
            {"user_id": user_id, "auth_token": auth_token, 'user_type': user_type, "last_login": last_login,
             "passwd_time_remaining": passwd_time_remaining.days})
        response.status_code = 200
        return response

    # This is the catch-all statement at the end of the method. If a conditional leaf doesn't return or raise
    # anything, it might overflow to here.
    raise get_error_response(400, "Only PUT requests are valid for this address")


# The frontend can use this address to ensure that it's still logged into the system
@app.route('/verify_logged_in', methods=['GET'])
def verify_logged_in():
    # Extract header information and ensure that no error is thrown
    requester_auth_token = get_header_verification_data(request, False)
    requester_user_id = str(db.get_user_id(auth_token=requester_auth_token))
    user_type = db.get_user_type(requester_user_id)
    response = jsonify(requester_user_id is not None and not requester_user_id == "None"
                       and not user_type == "new" and not user_type == "deactivated")
    # Always return a success code, regardless of if the user is logged in or not. The frontend will read the T/F value
    response.status_code = 200
    return response


@app.route('/register', methods=['GET', 'POST', 'PUT'])
def register():
    log_request(request)
    # Use the POST request to register a new user
    if request.method == 'POST':
        # Verify the request data
        json_data = request.get_json()
        assert_json_data_contains(['username', 'password', 'first_name', 'last_name', 'email'], json_data, "/register",
                                  "POST")
        username = json_data.get('username').strip()
        password = json_data.get('password').strip()
        first_name = json_data.get('first_name').strip()
        last_name = json_data.get('last_name').strip()
        email = json_data.get('email').strip()
        # Attempt to add the new user
        if not db.add_user(username, password, email, first_name, last_name, db.get_30_days_from_now()):
            raise get_error_response(400, "The account was not registered successfully")
        # Extract the authentication information and ensure the user was successfully registered
        user_id = db.get_user_id(username)
        auth_token = db.get_user_auth_token(username, password)
        if (user_id is None) or (auth_token is None):
            raise get_error_response(400, "The account was not registered successfully")
        # Since users are created as "new", a form of inactive account, they are unable to log in. Admins will need to
        # activate their account first
        response = jsonify({
            "message": "An admin will need to activate the account before logging in is permitted"})
        event_log.write(user_id, "Registered as a new user. User is now pending activation.")
        response.status_code = 200
        return response

    # This is the catch-all statement at the end of the method. If a conditional leaf doesn't return or raise
    # anything, it might overflow to here.
    raise get_error_response(400, "Only PUT requests are valid for this address")


@app.route('/user/<user_id>', methods=['GET', 'POST', 'PUT'])
def user(user_id):
    log_request(request)
    if user_id is None or user_id == "null":  # TODO Conduct a more thorough check
        raise get_error_response(400, "The URL must refer to a valid User ID, or be 'info' or 'all'")
    logging.debug("User ID: " + user_id)

    # Pre-authentication checks
    if request.method == 'GET' and user_id == 'info':
        response = jsonify({"user_types": db.user_types})
        response.status_code = 200
        return response

    # Authentication
    requester_auth_token, requester_user_id, requester_user_type = authenticate_request(request)

    # Use this to get a list of all users' information, or the information of a specific user
    if request.method == 'GET':
        # List of all users
        if user_id == 'all':
            assert_user_type_is(['admin'], requester_user_type)
            response = jsonify({"users": db.get_all_user_accounts()})
            response.status_code = 200
            return response

        # Single user
        else:
            if not str(requester_user_id) == str(user_id):
                assert_user_type_is(['admin'], requester_user_type)
            response = jsonify(db.get_user(user_id))
            response.status_code = 200
            return response

    # Use this to update the data of existing users
    if request.method == 'PUT':
        # Verify request data
        data = request.get_json()
        assert_json_data_contains(['category', 'value'], data, "user/<user_id>", "PUT")
        category = data.get('category')
        value = data.get('value')

        # Verify that the requester is either updating own account or is an admin
        if not (user_id == requester_user_id or requester_user_type == 'admin'):
            event_log.write(requester_user_id, "WARNING: A non-admin attempted to edit another user, " + user_id)
            raise get_error_response(403, "Only the given user or an admin can update a user's data")

        # Update Password
        # The password has to be done separately, since additional operations are performed while updating
        if category == 'password':
            logging.info("An admin (user_id: " + str(requester_user_id) +
                         ") is changing the password for a user (user_id: " + str(user_id) + ") to " + str(value))
            # Attempt to update the password
            if not db.update_password(user_id, value):
                raise get_error_response(405, "The password was not updated")
            logging.info("The password was updated successfully")
            event_log.write(requester_user_id, "Updated the password of user " + user_id)
            # Set the new expiration date
            db.set_password_expire(user_id, db.get_30_days_from_now())
            # Return success response
            response = jsonify({"message": "The password was updated successfully"})
            response.status_code = 200
            return response

        # Update general user information
        if category in ['first_name', 'last_name', 'email']:
            # Attempt to update the data
            if not db.set_user_data(user_id, category, value):
                raise get_error_response(405, "The data could not be set")
            event_log.write(requester_user_id, "Updated the " + category + " of user " + user_id)
            # Send the success response
            response = jsonify({"message": "The data was successfully set"})
            response.status_code = 200
            return response

        # Update user type
        if category == 'user_type':
            # Verify that the user is just an admin, and not someone trying to update their own user_type
            try:
                assert_user_type_is(['admin'], requester_user_type)
            except Exception as e:  # Catch it, log it, and throw it again
                event_log.write(requester_user_id, "WARNING: User is not admin and attempted to set the user_type "
                                + "of user " + user_id + " to " + value)
                raise e
            logging.info(
                "An admin (user_id: " + str(requester_user_id) +
                ") is changing the user_type for a user (user_id: " + str(user_id) + ") to " + str(value))
            # Attempt to update the user type
            if not db.set_user_type(user_id, value):
                raise get_error_response(405, "The user type could not be updated")
            logging.info("The user type was updated successfully")
            event_log.write(requester_user_id, "Set user " + user_id + " user_type to " + value)
            # Return the success response
            response = jsonify({"message": "The user type was updated successfully"})
            response.status_code = 200
            return response

    # Use this to create a new user as an admin (not for normal registration). To avoid conflicting POSTs to a single
    # user ID, use the address /user/new, and return the new user's ID
    if request.method == "POST":
        # Verify POSTer's user type
        if not db.get_user_type(requester_user_id) == "admin":
            event_log.write(requester_user_id, "WARNING: Made an invalid attempt to create a new user.")
            raise (403, "Only admins can add new users")
        # Verify URL. To avoid conflicting POSTs to a single user ID, the address /user/new must be used
        if not user_id == 'new':
            raise get_error_response(400, "POSTS only allowed on /user/new")
        # Verify request data
        json_data = request.get_json()
        assert_json_data_contains(['username', 'password', 'first_name', 'last_name', 'email', 'user_type'], json_data,
                                  "/user/new", "POST")
        # Attempt to create the user
        if not db.add_user(json_data['username'], json_data['password'], json_data['email'], json_data['first_name'],
                           json_data['last_name'], json_data['user_type']):
            raise get_error_response(400, "New user could not be added")
        # Retrieve the new user's ID
        new_user_id = db.get_user_id(json_data['username'])
        event_log.write(requester_user_id, "Created a new user with ID: " + str(new_user_id))
        if not db.set_user_type(new_user_id, json_data['user_type']):
            raise get_error_response(400, "The new user's account type could not be set")
        # Return the success response
        response = jsonify({"message": "The new user has been added", "user_id": str(new_user_id)})
        response.status_code = 200
        return response

    # This is the catch-all statement at the end of the method. If a conditional leaf doesn't return or raise
    # anything, it might overflow to here.
    raise get_error_response(400, "Only GET, PUT, and POST requests are valid for this address")


@app.route('/forgotpassword', methods=['GET', 'POST', 'PUT'])
def forgot_password():
    log_request(request)

    # Use a POST request when someone forgets their password
    if request.method == 'POST':
        # Verify request data
        data = request.get_json()
        assert_json_data_contains(['username'], data, "/forgotpassword", "PUT")
        username = data['username']
        # Verify user exists
        user_id = db.get_user_id(username)
        if user_id is None:
            raise get_error_response(400, "The username is not registered to an account")
        # Register the forgotten password with the database
        if not db.forgot_password(user_id):
            raise get_error_response(405, "The reset password request was not successfully registered")
        # Send the success response
        response = jsonify({"message": "An admin will need to reset your password."})
        response.status_code = 200
        return response

    # Use a GET request when an admin retrieves a list of who all needs their passwords reset
    if request.method == 'GET':
        # Authentication
        requester_auth_token, requester_user_id, requester_user_type = authenticate_request(request)
        # Verify that the requester is an admin
        assert_user_type_is(['admin'], requester_user_type)
        # Retrieve the files from the database
        data = db.get_forgotten_passwords()
        # Send the success response
        response = jsonify({"forgotten_passwords": data})
        response.status_code = 200
        return response

    # This is the catch-all statement at the end of the method. If a conditional leaf doesn't return or raise
    # anything, it might overflow to here.
    raise get_error_response(400, "Only GET and PUT requests are valid for this address")


# TODO Might delete this, we don't really need it
@app.route('/table/<table_name>', methods=['GET', 'POST', 'PUT'])
def get_table(table_name):
    if request.method == "GET":
        data = db.get_table(table_name)
        if data is None or len(table_name) == 0:
            raise get_error_response(404, "No table with the name " + table_name + " exists")
        response = jsonify(data)
        response.status_code = 200
        return response
    else:
        raise get_error_response(400, "Only GET requests are valid for this address")


@app.route('/account/<account_id>', methods=['GET', 'POST', 'PUT'])
def account(account_id):
    log_request(request)
    # Authentication
    requester_auth_token, requester_user_id, requester_user_type = authenticate_request(request)
    # Verify that the requester is a manager or regular user
    assert_user_type_is(['admin', 'manager', 'user'], requester_user_type)

    # Use a GET request to retrieve either a list of all accounts, or a single account
    if request.method == 'GET':
        # All accounts
        if account_id == "all":
            # Retrieve all viewable accounts
            accounts = db.get_viewable_accounts(requester_user_id)
            # Send success response
            response = jsonify({"accounts": accounts})
            response.status_code = 200
            return response
        # Single account
        else:
            # Attempt to retrieve the account
            if not db.get_user_has_account_access(requester_user_id, account_id):
                raise get_error_response(403, "You are not authorized to view this account.")
            data = db.get_account(account_id)
            # Send success response
            response = jsonify({"account": data})
            response.status_code = 200
            return response

    # Use a PUT request to update data about an existing account
    elif request.method == 'PUT':
        logging.info("This functionality has not been programmed yet (/account/<account_id>) 2")
        raise get_error_response(400, "This functionality has not been programmed yet (/account/<account_id>) 2")

    # Use a POST account to create a new account. Unlike creating users, the account ID is very important, so the POST
    # must be to that address
    elif request.method == 'POST':
        # Make sure only managers are using this
        assert_user_type_is(['manager'], requester_user_type)
        # Verify request data
        data = request.get_json()
        assert_json_data_contains(['account_title', 'normal_side', 'description'], data, 'account/' + account_id,
                                  'POST')
        account_title = data['account_title']
        normal_side = data['normal_side']
        description = data['description']
        # Make sure the account_id is an integer number
        try:
            int(account_id)
        except ValueError:
            raise get_error_response(400, "The account_id (/account/<account_id> must be an integer number")
        # Attempt to create the account
        if not db.add_account(account_id, account_title, normal_side, description, requester_user_id):
            event_log.write(requester_user_id, "WARNING: Unsuccessfully attempt to create Account " + account_id +
                            " with title \"" + account_title + "\"")
            raise get_error_response(400, "The account was not successfully created")
        event_log.write(requester_user_id, "Created Account " + account_id + " with title \"" + account_title + "\"")
        # Send success response
        response = jsonify({"message": "The account was successfully created"})
        response.status_code = 200
        return response

    # This is the catch-all statement at the end of the method. If a conditional leaf doesn't return or raise
    # anything, it might overflow to here.
    raise get_error_response(404, "Not sure how you got here... that's not supposed to happen...")


@app.route('/eventlog/<user_id>', methods=['GET', 'POST', 'PUT'])
def get_event_log(user_id):
    log_request(request)
    # Add a debug dump
    if user_id == "dump":
        event_log.dump()
        response = jsonify({"message": "Event Log dumped to debug log"})
        response.status_code = 200
        return response
    # Authentication
    requester_auth_token, requester_user_id, requester_user_type = authenticate_request(request)
    # Verify that the requester is a manager or regular user
    assert_user_type_is(['admin', 'manager'], requester_user_type)  # TODO Managers?

    # Use a GET request to retrieve either a list of events for all users, or a list of events for a single user
    if request.method == "GET":
        if user_id == "all":
            # Send success response
            response = jsonify(event_log.get_all())
            response.status_code = 200
            return response
        else:
            # Send success response
            response = jsonify(event_log.get_from_user(user_id))
            response.status_code = 200
            return response

    # This is the catch-all statement at the end of the method. If a conditional leaf doesn't return or raise
    # anything, it might overflow to here.
    raise get_error_response(400, "Only GET requests are valid for this address")


@app.route('/journal/<journal_entry_id>', methods=['GET', 'POST', 'PUT'])
def journal(journal_entry_id):
    log_request(request)
    # Authentication
    requester_auth_token, requester_user_id, requester_user_type = authenticate_request(request)
    # Verify that the requester is a manager or regular user
    assert_user_type_is(['manager', 'user'], requester_user_type)

    # Use a GET request to retrieve either a list of all journal entries, or a single journal entry
    if request.method == 'GET':
        # All accounts
        if journal_entry_id == "all":
            # Retrieve all viewable journal entries
            journal_entries = db.get_viewable_journal_entries(requester_user_id)
            # Send success response
            response = jsonify({"journal_entries": journal_entries})
            response.status_code = 200
            return response
        # Single account
        else:
            # Attempt to retrieve the journal entry
            if not db.get_user_has_journal_access(requester_user_id, journal_entry_id):
                raise get_error_response(403, "You are not authorized to view this journal entry.")
            data = db.get_journal_entry(journal_entry_id)
            # Send success response
            response = jsonify({"journal_entry": data})
            response.status_code = 200
            return response

    # Use a PUT request to update data about an existing journal entry
    elif request.method == 'PUT':
        # Verify only manager
        assert_user_type_is(['manager'], requester_user_type)
        # Verify request data
        data = request.get_json()
        assert_json_data_contains(['category', 'value'], data, "user/<user_id>", "PUT")
        category = data.get('category')
        value = data.get('value')
        # Verify valid category
        if category not in ['status', 'description']:
            raise get_error_response(400, "The category must be either 'status' or 'description'")
        # Check if posting
        if category == 'status':
            if not db.get_journal_entry_data(journal_entry_id, 'status') == "pending":
                raise get_error_response(400, "Only pending journal entries can be posted or rejected")
            if value not in ['posted', 'rejected']:
                raise get_error_response(400, "Journal entries can only be posted or rejected")
            if value == 'posted':
                if not db.set_journal_entry_data(journal_entry_id, category, value):
                    raise get_error_response(500, "The journal entry could not be posted")
                if not db.set_journal_entry_data(journal_entry_id, "POSTING_MANAGER", requester_user_id):
                    raise get_error_response(500, "The posting manager could not be set")
                # TODO Set Separate Posting Reference
                if not db.set_journal_entry_data(journal_entry_id, "POSTING_REFERENCE", journal_entry_id):
                    raise get_error_response(500, "The posting reference could not be set")
                response = jsonify({"message": "The journal entry was successfully posted"})
                response.status_code = 200
                return response
            if value == 'rejected':
                assert_json_data_contains(['description'], data, "user/<user_id>", "PUT")
                description = data.get('description')
                if not db.set_journal_entry_data(journal_entry_id, category, value):
                    raise get_error_response(405, "The journal entry could not be rejected")
                if not db.set_journal_entry_data(journal_entry_id, "DESCRIPTION", description):
                    raise get_error_response(405, "The journal entry could not be posted")
                response = jsonify({"message": "The journal entry was successfully rejected"})
                response.status_code = 200
                return response
        # Attempt to update the data
        if not db.set_journal_entry_data(journal_entry_id, category, value):
            raise get_error_response(405, "The journal entry could not be updated")
        event_log.write(requester_user_id, "Updated the " + category + " of journal entry " + journal_entry_id)
        # Send the success response
        response = jsonify({"message": "The data was successfully set"})
        response.status_code = 200
        return response

    # Use a POST account to create a new journal entry. The journal entry ID is not very important, so POST to
    # /journal/new to avoid collisions
    elif request.method == 'POST':
        # Make sure only managers are using this
        assert_user_type_is(['manager', 'user'], requester_user_type)
        # Verify URL. To avoid conflicting POSTs to a single journal ID, the address /journal/new must be used
        if not journal_entry_id == 'new':
            raise get_error_response(400, "POSTS only allowed on /journal/new")
        # Verify request data
        data = request.get_json()
        assert_json_data_contains(['transactions_list', 'date', 'description', 'journal_type'], data,
                                  'journal/' + journal_entry_id, 'POST')
        transactions_list = data['transactions_list']
        date = data['date']
        description = data['description']
        journal_type = data['journal_type']
        if not isinstance(transactions_list, list):
            raise get_error_response(400, "The transactions must be sent as a list")
        debit_side_sum = 0
        credit_side_sum = 0
        for transaction in transactions_list:
            if transaction['account_id'] is None or transaction['account_id'] == "":
                raise get_error_response(400, "Each transaction must contain an account ID")
            if transaction['amount'] is None or transaction['amount'] == "":
                raise get_error_response(400, "Each transaction must contain an amount")
            try:
                amount = float(transaction['amount'])
                logging.debug(str(amount))
                if amount > 0:
                    debit_side_sum += amount
                if amount < 0:
                    credit_side_sum += amount
            except ValueError:
                raise get_error_response(400, "The transaction amount must be a number")
        logging.debug("Credit: " + str(credit_side_sum) + "\tDebit: " + str(debit_side_sum))
        if debit_side_sum == 0 or credit_side_sum == 0:
            raise get_error_response(400, "Each journal entry must contain a debit and a credit")
        if not debit_side_sum + credit_side_sum == 0:
            raise get_error_response(400, "Credits and Debits must be equal")
        # Attempt to create journal entry in database
        new_journal_entry_id = db.create_journal_entry(transactions_list, requester_user_id, date, description,
                                                       journal_type)
        event_log.write(requester_user_id, "Created a journal entry with ID: " + str(new_journal_entry_id))
        # Provision a folder for source docs to be uploaded to
        if os.path.isdir(app.config['UPLOAD_FOLDER'] + str(new_journal_entry_id)):
            logging.warning('The folder for a journal entry\'s files already exists. Its contents will be deleted.')
            for a_file in os.listdir(app.config['UPLOAD_FOLDER'] + str(new_journal_entry_id)):
                path = os.path.join(app.config['UPLOAD_FOLDER'] + str(new_journal_entry_id), a_file)
                try:
                    os.unlink(path)
                except Exception:
                    logging.warning('There was an error deleting the folder\'s contents.')
        else:
            os.mkdir(os.path.join(app.config['UPLOAD_FOLDER'], str(new_journal_entry_id)))
        # Send success response
        response = jsonify({"message": "The journal entry was successfully created",
                            "upload_folder": "https://" + config['host']['base_path'] + "journal/" +
                                             str(new_journal_entry_id) + "/"})
        response.status_code = 200
        return response

    # This is the catch-all statement at the end of the method. If a conditional leaf doesn't return or raise
    # anything, it might overflow to here.
    raise get_error_response(404, "Not sure how you got here... that's not supposed to happen...")


@app.route('/files/<journal_entry_id>/', methods=['GET', 'POST'])
def upload_files(journal_entry_id):
    log_request(request)

    # Authentication
    requester_auth_token, requester_user_id, requester_user_type = authenticate_request(request)
    # Verify that the requester is a manager or regular user
    assert_user_type_is(['manager', 'user'], requester_user_type)

    # Verify that the correct directory exists
    if not os.path.isdir(app.config['UPLOAD_FOLDER'] + str(journal_entry_id)):
        raise get_error_response(403, "The given address is not associated with an existing journal entry.")

    # POST a new file
    if request.method == 'POST':
        # Check that a file was sent
        if 'file' not in request.files:
            raise get_error_response(400, 'A file must be sent in a POST to this address')
        file = request.files['file']
        # Check that the file has a name
        if file.filename == '':
            raise get_error_response(400, 'The file must be named')
        # Check the file type
        if not allowed_file(file.filename):
            raise get_error_response(403, 'A file of that filetype is not allowed on this server')
        # Save the file
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    # GET a list of files in a directory
    if request.method == 'GET':
        return_files = list()
        for (dirpath, dirnames, filenames) in os.walk(app.config['UPLOAD_FOLDER'] + str(journal_entry_id)):
            return_files.extend(filenames)
            break  # Break so it only gets the top director and excludes subdirectory files, if there are any
        response = jsonify({'filenames': return_files})
        response.status_code = 200
        return response

    # This is the catch-all statement at the end of the method. If a conditional leaf doesn't return or raise
    # anything, it might overflow to here.
    raise get_error_response(404, "Not sure how you got here... that's not supposed to happen...")


@app.route('/files/<journal_entry_id>/<filename>', methods=['GET'])
def download_files(journal_entry_id, filename):
    log_request(request)
    # Authentication
    requester_auth_token, requester_user_id, requester_user_type = authenticate_request(request)
    # Verify that the requester is a manager or regular user
    assert_user_type_is(['manager', 'user'], requester_user_type)
    # Send file
    return send_from_directory(app.config['UPLOAD_FOLDER'] + str(journal_entry_id), filename)


def get_error_response(status_code, message):
    """This automatically generates an error response, it needs to be thrown once returned to be effective."""
    return PostitHTTPError(message, status_code)


@app.errorhandler(PostitHTTPError)
def handle_http_error(error):
    """This handles all HTTPErrors thrown within this program. It converts the exception into an appropriate HTTP
    response"""
    logging.info(error.message)
    response = jsonify(error.to_dict())
    try:
        response.status_code = error.status_code
    except AttributeError:
        response.status_code = 400
    return response


def dict2string(dictionary):
    """This converts a dict into a string for well-formatted printing"""
    if dictionary is None:
        return ""
    return_string = ""
    return_string += str("{\n")
    for key in list(dictionary.keys()):
        return_string += str(key + ": ")
        if isinstance(dictionary[key], dict):
            return_string += str(dict2string(dictionary[key]))
        elif isinstance(dictionary[key], list):
            return_string += str(list2string(dictionary[key]))
        else:
            logging.debug(dictionary[key])
            return_string += str(dictionary[key]) + "\n"
    return_string += str("}")
    logging.debug(return_string)
    return return_string


def list2string(lizt):
    if lizt is None:
        return ""
    return_string = ""
    return_string += str("[\n")
    for item in lizt:
        if item is dict:
            return_string += str(dict2string(item))
        elif item is list:
            return_string += str(list2string(item))
        else:
            return_string += str(item) + "\n"
    return_string += str("]\n")
    logging.debug(return_string)
    return return_string


def log_request(request):
    """This logs a request into the default debug log"""
    logging.debug("==========================================================")
    logging.debug("Got a " + request.method + " for " + request.url)
    logging.debug("Headers: " + dict2string(request.headers))
    if request is not None:
        logging.debug("JSON Data: " + dict2string(request.get_json()))
        logging.debug("Data: " + str(request.data))
        logging.debug("Form: " + dict2string(request.form))
    logging.debug(str(request))


def verify_user(auth_token, user_id):  # TODO Remember what this does and document...
    return db.verify_user(auth_token, user_id)


def get_header_verification_data(request, throw_exception=True):
    """Retrieves the header authentication data and throws an error (if set to true) if there is no auth data in the
    header"""
    auth_block = request.headers.get('Authorization')
    if auth_block is not None:
        logging.debug("Auth Block: " + auth_block)
        if "Bearer" in auth_block:
            auth_token = auth_block[7:]
        else:
            auth_token = auth_block
    else:
        auth_token = None

    logging.debug("Extracted Authorization: " + auth_token if auth_token is not None else "None")

    if auth_token is None and throw_exception:
        logging.debug("Throw exception: " + str(throw_exception))
        raise get_error_response(401, "The authorization must be sent in the header")

    return auth_token


def assert_json_data_contains(keys_list, json_data, url, request_method):
    """Convenience method for checking json data and throwing error when expected data is missing

    This checks the given json data to ensure each key from the keys_list is in the data, and that the associated
    value is not null"""
    missing_keys = list()

    for key in keys_list:
        data = json_data.get(key)
        if data is None or data == "":
            missing_keys.append(key)

    if len(missing_keys) == 0:
        return

    message = "A " + request_method + " to " + url + " must include the keys: "
    for key in missing_keys:
        message += key + ", "

    raise get_error_response(400, message)


def assert_user_type_is(user_types, requester_user_type):
    """Convenience method for checking user types and throwing error"""
    if requester_user_type not in user_types:
        raise get_error_response(403, "A user of type " + requester_user_type + " is unable to perform this operation.")


def authenticate_request(request):
    """Convenience method for authenticating a user"""
    requester_auth_token = get_header_verification_data(request)
    requester_user_id = db.get_user_id(auth_token=requester_auth_token)
    user_type = db.get_user_type(requester_user_id)
    if not verify_user(requester_auth_token, requester_user_id):
        raise get_error_response(403, "The requester is not a verified user")
    if user_type == "new" or user_type == "deactivated":
        raise get_error_response(403, "This account is deactivated, please contact an administrator")
    return requester_auth_token, requester_user_id, user_type


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower in config['files']['allowed_extensions']


if __name__ == "__main__":
    logging.basicConfig(filename=os.getcwd() + "error.log")
    app.run(host=config['host']['hostname'], debug=True)
