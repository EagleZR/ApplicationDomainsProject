from ledger import databasecontroller
from ledger.EventLog import EventLog
from flask import (Flask, request, jsonify)
from datetime import datetime
from flask_cors import CORS
from ledger.HTTPError import HTTPError
import configparser
import os.path
import logging

from ledger.databasecontroller.SQLITEDatabaseController import DuplicateIDException, InvalidUserType

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/config.ini')
db = databasecontroller.get_database(config['database']['database_type'])
app = Flask(__name__)
CORS(app)
event_log = EventLog()


@app.route('/')
def hello_world():
    return 'Server is up'


@app.route('/info', methods=['GET', 'POST', 'PUT'])
def site_info():
    log_request(request)

    if request.method == 'GET':
        return jsonify({"response": "It worked!"})
    raise get_error_response(400, "Only GET requests are valid for this address")


@app.route('/signin', methods=['GET', 'POST', 'PUT'])
def login():
    log_request(request)

    if request.method == 'PUT':
        logging.debug("Working PUT request in /signin")
        json_data = request.get_json()
        logging.debug("Extracted JSON data in /signin")
        if json_data is not None:
            logging.debug("JSON data is not null in /signin")
            username = json_data.get('username')
            password = json_data.get('password')
            user_id, auth_token, last_login, password_expire_date = db.get_login_data(username, password)
            if (user_id is None) or (auth_token is None) or (password_expire_date is None):
                raise get_error_response(403, "The username/password is invalid.")
            passwd_time_remaining = password_expire_date - datetime.today()
            if passwd_time_remaining.days < 0:
                return get_error_response(403, "Your password has expired, please contact an administrator")
            account_type = db.get_account_type(user_id)
            logging.debug("account_type extracted in /signin")
            if account_type == "deactivated" or account_type == "new":
                raise get_error_response(403, "The user account is not active. Please contact an administrator.")
            logging.debug("Account type is valid in /signin")
            db.update_last_login(user_id, datetime.today())
            response = jsonify({"message": {"user_id": user_id, "auth_token": auth_token, "last_login": last_login,
                                            "passwd_time_remaining": passwd_time_remaining.days}})
            logging.debug("Returning JSON object in /signin")
            response.status_code = 200
            logging.debug(response)
            return response
        else:
            raise get_error_response(400, "Please include both the username and the password")
    else:
        raise get_error_response(400, "Only PUT requests are valid for this address")


@app.route('/register', methods=['GET', 'POST', 'PUT'])
def register():
    log_request(request)

    if request.method == 'PUT':
        json_data = request.get_json()
        if json_data is not None:
            username = json_data.get('username')
            password = json_data.get('password')
            name = json_data.get('name')
            if db.add_user(username, password, name, db.get_30_days_from_now()):
                user_id = db.get_user_id(username)
                auth_token = db.get_user_auth_token(username, password)
                if (user_id is None) or (auth_token is None):
                    raise get_error_response(400, "The account was not registered successfully")
                response = jsonify({
                    "message": "An admin will need to activate the account before logging in is permitted"})
                response.status_code = 200
                return response
            else:
                raise get_error_response(400, "The account was not registered successfully")
        else:
            raise get_error_response(400, "Please include the username, password, ")
    else:
        raise get_error_response(400, "Only PUT requests are valid for this address")


@app.route('/user/<user_id>', methods=['GET', 'POST', 'PUT'])
def user(user_id):
    log_request(request)

    if request.method == 'GET' and user_id == 'info':
        # Short circuit the authentication
        response = jsonify({"message": {"account_types": db.account_types}})
        response.status_code = 200
        return response

    requester_auth_token = get_header_verification_data(request)
    requester_user_id = db.get_user_id(auth_token=requester_auth_token)
    user_type = db.get_account_type(requester_user_id)

    logging.debug("Requester is a " + user_type)

    if not verify_user(requester_auth_token, requester_user_id):
        raise get_error_response(403, "The requester is not a verified user")

    if request.method == 'GET':
        if user_id == 'all':
            logging.debug("User type: " + user_type)
            if user_type == 'admin':
                return jsonify({"message": db.get_all_user_accounts()})
            else:
                raise get_error_response(403, "This user is not authorized to view this information.")
        else:
            logging.info("This functionality has not been programmed yet (/account/<user_id>) 1")
            raise get_error_response(400, "This functionality has not been programmed yet (/account/<user_id>) 1")
    if request.method == 'PUT':
        data = request.get_json()
        if data is not None:
            category = data.get('category')
            value = data.get('value')
            if user_id == requester_user_id:
                if category == 'password':
                    logging.info("User " + user_id + " is updating their password.")
                    if db.update_password(user_id, value):
                        db.set_password_expire(user_id, db.get_30_days_from_now())
                        logging.info("The account was updated successfully")
                        response = jsonify({"message": "The account was updated successfully"})
                        response.status_code = 200
                        return response
                    else:
                        logging.error("The account was not updated")
                        response = jsonify({"message": "The account was not updated"})
                        response.status_code = 500
                        return response
                else:
                    logging.info("This functionality has not been programmed yet (/account/<user_id>) 2")
                    raise get_error_response(400,
                                             "This functionality has not been programmed yet (/account/<user_id>) 2")
            elif user_type == 'admin':
                if category == 'account_type':
                    logging.info(
                        "An admin (user_id: " + str(requester_user_id) + ") is changing the account_type for a user "
                                                                         "(user_id: " + str(user_id) + ") to " + str(
                            value))
                    if db.set_account_type(user_id, value):
                        logging.info("The account was updated successfully")
                        response = jsonify({"message": "The account was updated successfully"})
                        response.status_code = 200
                        return response
                    else:
                        logging.error("The account was not updated")
                        response = jsonify({"message": "The account was not updated"})
                        response.status_code = 500
                        return response
                elif category == 'password':
                    logging.info(
                        "An admin (user_id: " + str(requester_user_id) + ") is changing the password for a user "
                                                                         "(user_id: " + str(user_id) + ") to " + str(
                            value))
                    if db.update_password(user_id, value):
                        db.set_password_expire(user_id, db.get_30_days_from_now())
                        logging.info("The account was updated successfully")
                        response = jsonify({"message": "The account was updated successfully"})
                        response.status_code = 200
                        return response
                    else:
                        logging.error("The account was not updated")
                        response = jsonify({"message": "The account was not updated"})
                        response.status_code = 500
                        return response
                else:
                    logging.info("This functionality has not been programmed yet (/account/<user_id>) 3")
                    raise get_error_response(400,
                                             "This functionality has not been programmed yet (/account/<user_id>) 3")
            else:
                logging.info("This functionality has not been programmed yet (/account/<user_id>) 4")
                raise get_error_response(400, "This functionality has not been programmed yet (/account/<user_id>) 4")
        else:
            logging.info("The PUT request does not contain any data")
            raise get_error_response(400, "The PUT request does not contain any data")
    raise get_error_response(400, "Only GET and PUT requests are valid for this address")


@app.route('/forgotpassword', methods=['GET', 'POST', 'PUT'])
def forgot_password():
    log_request(request)

    data = request.get_json()

    if request.method == 'PUT':
        username = data['username']
        if username is not None:
            user_id = db.get_user_id(username)
            if user_id is not None:
                db.forgot_password(user_id)
                response = jsonify({"message": "An admin will need to reset your password."})
                response.status_code = 200
                return response
            else:
                return get_error_response(400, "The username is not registered to an account")
        else:
            return get_error_response(400, "The username must be included in the PUT request")
    if request.method == 'GET':
        requester_auth_token = get_header_verification_data(request)
        requester_user_id = db.get_user_id(auth_token=requester_auth_token)
        user_type = db.get_account_type(requester_user_id)
        if user_type == 'admin':
            data = db.get_forgotten_passwords()
            response_list = list()
            for user_data in data:
                response_list.append({"user_id": user_data[0], "username": db.get_username(user_data[0]),
                                      "date_forgotten": user_data[1], "last_login": db.get_last_login(user_data[0])})
            response = jsonify({"message": response_list})
            response.status_code = 200
            return response
        else:
            return get_error_response(403, "Only an admin can access this feature")
    else:
        return get_error_response(400, "Only GET and PUT requests are valid for this address")


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
        return get_error_response(400, "Only GET requests are valid for this address")


@app.route('/account/<account_id>', methods=['GET', 'POST', 'PUT'])
def account(account_id):
    log_request(request)

    requester_auth_token = get_header_verification_data(request)
    requester_user_id = str(db.get_user_id(auth_token=requester_auth_token))
    user_type = db.get_account_type(requester_user_id)

    if requester_auth_token is None and requester_user_id is None:
        raise get_error_response(403, "You must be logged in to view this information.")

    if request.method == 'GET':
        if account_id == "all":
            accounts = db.get_viewable_accounts(requester_user_id)
            response = jsonify({"message": {"accounts": accounts}})
            response.status_code = 200
            return response
        if db.get_user_has_account_access(requester_user_id, account_id):
            data = db.get_account(account_id)
            response = jsonify({"message": data})
            response.status_code = 200
            return response
        else:
            raise get_error_response(403, "You are not authorized to view this account.")
    elif request.method == 'PUT':
        logging.info("This functionality has not been programmed yet (/account/<account_id>) 2")
        raise get_error_response(400, "This functionality has not been programmed yet (/account/<account_id>) 2")
    elif request.method == 'POST':
        if not user_type == "admin" and not user_type == "manager":
            event_log.write(
                "User " + requester_user_id + " attempted to create an account without authorization. User "
                                              "is only a " + user_type)
            raise get_error_response(403, "Only an admin or a manager can create an account")

        data = request.get_json()
        if data is None:
            raise get_error_response(400, "The request must contain the account_title, normal_side, and description")

        try:
            int(account_id)
        except ValueError:
            raise get_error_response(400, "The account_id (/account/<account_id> must be an integer number")

        account_title = data['account_title']
        if account_title is None:
            raise get_error_response(400, "The account_title must be included with a POST request.")
        normal_side = data['normal_side']
        if normal_side is None:
            raise get_error_response(400, "The normal_side must be included with a POST request.")
        if not (normal_side == "left" or normal_side == "right"):
            raise get_error_response(400, "The normal_side must be either \"left\" or \"right\"")
        description = data['description']
        if description is None:
            raise get_error_response(400, "The description must be included with a POST request.")

        event_log.write("User " + requester_user_id + " is attempting to create account " + account_id +
                        " with a title of \"" + account_title + "\"")

        if db.add_account(account_id, account_title, normal_side, description):
            event_log.write("User " + requester_user_id + " successfully created account " + account_id +
                            " with a title of \"" + account_title + "\"")
            response = jsonify({"message": "The account was successfully created"})
            response.status_code = 200
            return response
        else:
            event_log.write("User " + requester_user_id + " was not successful in creating account " + account_id +
                            " with a title of \"" + account_title + "\"")
            raise get_error_response(400, "The account was not successfully created")
    else:
        raise get_error_response(404, "Not sure how you got here... that's not supposed to happen...")


@app.route('/eventlog', methods=['GET', 'POST', 'PUT'])
def get_event_log():
    log_request(request)
    if request.method == "GET":

        requester_auth_token = get_header_verification_data(request)
        requester_user_id = db.get_user_id(auth_token=requester_auth_token)
        user_type = db.get_account_type(requester_user_id)

        if requester_auth_token is None or requester_user_id is None:
            raise get_error_response(403, "You must be logged in to view this information.")

        if not user_type == "admin":  # TODO Verify this needs to be checked
            event_log.write(
                "User " + str(requester_user_id) + " attempted to view the event log, but is only a " + user_type)
            logging.warning(
                "User " + str(requester_user_id) + " attempted to view the event log, but is only a " + user_type)
            raise get_error_response(403, "You must be an admin to view this information.")

        response = jsonify(event_log.read_all())
        response.status_code = 200
        return response
    else:
        return get_error_response(400, "Only GET requests are valid for this address")


def get_error_response(status_code, message):
    return HTTPError(message, status_code)


@app.errorhandler(HTTPError)
def handle_http_error(error):
    logging.info(error.message)
    response = jsonify(error.to_dict())
    try:
        response.status_code = error.status_code
    except AttributeError:
        response.status_code = 400
    return response


def dict2string(dictionary):
    if dictionary is None:
        return ""
    return_string = "{\n"
    for key in list(dictionary.keys()):
        return_string += key + ": "
        if dictionary[key] is dict:
            return_string += dict2string(dictionary[key])
        else:
            return_string += dictionary[key] + ", \n"
    return_string += "}"
    return return_string


def log_request(request):
    logging.debug("==========================================================")
    logging.debug("Got a " + request.method + " for " + request.url)
    logging.debug("Headers: " + dict2string(request.headers))
    if request is not None:
        logging.debug("JSON Data: " + dict2string(request.get_json()))
        logging.debug("Data: " + str(request.data))
        logging.debug("Form: " + dict2string(request.form))
    logging.debug(str(request))


def verify_user(auth_token, user_id):
    return db.verify_user(auth_token, user_id)


def get_header_verification_data(request):
    auth_block = request.headers.get('Authorization')
    if auth_block is not None:
        auth_token = auth_block[7:]
    else:
        auth_token = None

    logging.debug("Extracted Authorization: " + auth_token if auth_token is not None else "None")

    if auth_token is None:
        raise get_error_response(400, "The authorization must be sent in the header")

    return auth_token


if __name__ == "__main__":
    logging.basicConfig(filename=os.getcwd() + "error.log")
    app.run(host=config['host']['hostname'], debug=True)
