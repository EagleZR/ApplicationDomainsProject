from ledger import databasecontroller
from flask import (Flask, request, jsonify)
from ledger.HTTPError import HTTPError
from datetime import (datetime)
import configparser
import os.path
import logging

from ledger.databasecontroller.SQLITEDatabaseController import DuplicateEmailException, InvalidUserType

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/config.ini')
db = databasecontroller.get_database(config['database']['database_type'])
app = Flask(__name__)


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
            email = json_data.get('username')
            password = json_data.get('password')
            user_id, auth_token, last_login, password_expire_date_string = db.get_login_data(email, password)
            if (user_id is None) or (auth_token is None) or (password_expire_date_string is None):
                raise get_error_response(403, "The email/password is invalid.")
            else:
                logging.debug("user_id and auth_token are not null in /signin")
            password_expire_date = datetime.strptime(password_expire_date_string, db.date_string_format)
            passwd_time_remaining = datetime.today() - password_expire_date
            account_type = db.get_account_type(user_id)
            logging.debug("account_type extracted in /signin")
            if account_type == "deactivated" or account_type == "new":
                raise get_error_response(403, "The user account is not active. Please contact an administrator.")
            logging.debug("Account type is valid in /signin")
            db.update_last_login(user_id, datetime.today().strftime(db.date_string_format))
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
            email = json_data.get('username')
            password = json_data.get('password')
            name = json_data.get('name')
            if db.add_user(email, password, name, db.get_30_days_from_now()):
                user_id = db.get_user_id(email, password)
                auth_token = db.get_user_auth_token(email, password)
                if (user_id is None) or (auth_token is None):
                    raise get_error_response(403, "The account was not registered successfully")
                # response = jsonify({"user_id": user_id, "auth_token": auth_token})
                # The account will need to be activated by an admin before the user can log in
                response = jsonify({
                    "message": "An admin will need to activate the account before logging in is permitted"})
                response.status_code = 200
                return response
            else:
                raise get_error_response(403, "The account was not registered successfully")
        else:
            raise get_error_response(400, "Please include the email, password, ")
    else:
        raise get_error_response(400, "Only PUT requests are valid for this address")


@app.route('/user/<user_id>', methods=['GET', 'POST', 'PUT'])
def account(user_id):
    log_request(request)

    if request.method == 'GET' and user_id == 'info':
        # Short circuit the authentication
        response = jsonify({"message": {"account_types": db.account_types}})
        response.status_code = 200
        return response

    requester_auth_token = get_header_verification_data(request)
    requester_user_id = db.get_user_id(auth_token=requester_auth_token)
    user_type = db.get_account_type(requester_user_id)

    data = request.get_json()

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
            logging.info("This functionality has not been programmed yet (/account/<user_id>)")
    elif request.method == 'PUT':
        logging.info("This functionality has not been programmed yet (/account/<user_id>)")
    elif request.method == 'POST':
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
                    logging.info("This functionality has not been programmed yet (/account/<user_id>)")
            elif user_type == "admin":
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
                    logging.info("This functionality has not been programmed yet (/account/<user_id>)")
            else:
                logging.info("This functionality has not been programmed yet (/account/<user_id>)")
        else:
            logging.info("The POST request does not contain any data")
            raise get_error_response(400, "The POST request does not contain any data")
    raise get_error_response(400, "Only GET and PUT requests are valid for this address")


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


# Flask uses exceptions for redirecting and other operations, so can't catch all like this
# @app.errorhandler(Exception)
# def handle_any_error(error):
#     logging.info(error)
#     try:
#         logging.info(error.message)
#         response = jsonify({"message": error.message})
#     except AttributeError:
#         response = jsonify({"message": "none"})
#     response.status_code = 500
#     # TODO Print exception and stack trace
#     return response


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
    auth_token = request.headers.get('Authorization')[7:]

    logging.debug("Extracted Authorization: " + auth_token)

    if auth_token is None:
        raise get_error_response(400, "The authorization must be sent in the header")

    return auth_token


if __name__ == "__main__":
    logging.basicConfig(filename=os.getcwd() + "error.log")
    app.run(host=config['host']['hostname'], debug=True)
