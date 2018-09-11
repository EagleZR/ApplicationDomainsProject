from ledger import databasecontroller
from flask import (Flask, request, jsonify)
from ledger.HTTPError import HTTPError
import configparser
import os.path
import logging

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/config.ini')
db = databasecontroller.get_database(config['database']['database_type'])
app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello World'


@app.route('/info', methods=['GET', 'POST', 'PUT'])
def site_info():
    logging.info("Got a " + request.method + " for " + request.url + "from " + request.host_url)
    if request.method == 'GET':
        return jsonify({"response": "It worked!"})
    raise get_error_response(400, "Only GET requests are valid for this address")


@app.route('/signin', methods=['GET', 'POST', 'PUT'])
def login():
    logging.info("Got a " + request.method + " for " + request.url + "from " + request.host_url)
    if request.method == 'PUT':
        json_data = request.get_json()
        if json_data is not None:
            email = json_data.get('email')
            password = json_data.get('password')
            user_id, auth_token = db.get_login_data(email, password)
            if (user_id is None) or (auth_token is None):
                raise get_error_response(403, "The email/password is invalid")
            response = jsonify({"user_id": user_id, "auth_token": auth_token})
            response.status_code = 200
            return response
        else:
            raise get_error_response(400, "Please include both the username and the password")
    else:
        raise get_error_response(400, "Only PUT requests are valid for this address")


@app.route('/register', methods=['GET', 'POST', 'PUT'])
def register():
    logging.info("Got a " + request.method + " for " + request.url + "from " + request.host_url)
    if request.method == 'PUT':
        json_data = request.get_json()
        if json_data is not None:
            email = json_data.get('email')
            password = json_data.get('password')
            name = json_data.get('name')
            if db.add_user(email, password, name):
                user_id = db.get_user_id(email, password)
                auth_token = db.get_user_auth_token(email, password)
                if (user_id is None) or (auth_token is None):
                    raise get_error_response(403, "The account was not registered successfully")
                response = jsonify({"user_id": user_id, "auth_token": auth_token})
                response.status_code = 200
                return response
            else:
                raise get_error_response(403, "The account was not registered successfully")
        else:
            raise get_error_response(400, "Please include the email, password, ")
    else:
        raise get_error_response(400, "Only PUT requests are valid for this address")


@app.route('/account', methods=['GET', 'POST', 'PUT'])
def account():
    if request.method == 'GET':
        pass
    elif request.method == 'PUT':
        pass
    else:
        raise get_error_response(400, "Only GET and PUT requests are valid for this address")


def get_error_response(status_code, message):
    return HTTPError(message, status_code)


@app.errorhandler(HTTPError)
def handle_http_error(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


if __name__ == "__main__":
    logging.basicConfig(filename=os.getcwd() + "error.log")
    app.run(host=config['host']['hostname'], debug=True)
