from ledger import databasecontroller
from flask import (Flask, request, jsonify)
from ledger.HTTPError import HTTPError
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
    return 'Hello World'


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
        json_data = request.get_json()
        if json_data is not None:
            email = json_data.get('username')
            password = json_data.get('password')
            user_id, auth_token = db.get_login_data(email, password)
            if (user_id is None) or (auth_token is None):
                raise get_error_response(403, "The email/password is invalid.")
            account_type = db.get_account_type(user_id)
            if account_type == "deactivated" or account_type == "pending":
                raise get_error_response(403, "The user account is not active. Please contact an administrator.")
            response = jsonify({"user_id": user_id, "auth_token": auth_token})
            response.status_code = 200
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
            if db.add_user(email, password, name):
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


@app.route('/account/<user_id>', methods=['GET', 'POST', 'PUT'])
def account(user_id):
    log_request(request)

    requester_auth_token, requester_user_id = get_header_verification_data(request)

    data = request.get_json()

    if not verify_user(requester_auth_token, requester_user_id):
        raise get_error_response(403, "The requester is not a verified user")

    if request.method == 'GET':
        if user_id == 'all':
            if db.get_account_type(requester_user_id) == 'admin':
                db.get_all_user_accounts()
            else:
                raise get_error_response(403, "This user is not authorized to view this information.")
        else:
            logging.info("This functionality has not been programmed yet (/account/<user_id>)")
    elif request.method == 'PUT':
        pass  # Analyze request data for what changed and save it to the db
    else:
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
    logging.info("Got a " + request.method + " for " + request.url)
    logging.info("Headers: " + dict2string(request.headers))
    if request is not None:
        logging.info("JSON Data: " + dict2string(request.get_json()))
        logging.info("Data: " + str(request.data))
        logging.info("Form: " + dict2string(request.form))
    logging.info(str(request))


def verify_user(auth_token, user_id):
    return db.verify_user(auth_token, user_id)


def get_header_verification_data(request):
    auth_token = request.headers.get('auth_token')
    user_id = request.headers.get('user_id')

    if auth_token is None and user_id is None:
        raise get_error_response(400, "The auth_token and user_id must be sent in the header")
    if auth_token is None:
        raise get_error_response(400, "The auth_token must be sent in the header")
    if user_id is None:
        raise get_error_response(400, "The user_id must be sent in the header")

    return auth_token, user_id


if __name__ == "__main__":
    logging.basicConfig(filename=os.getcwd() + "error.log")
    app.run(host=config['host']['hostname'], debug=True)
