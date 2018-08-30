from ledger import databasecontroller
from flask import (Flask, request, jsonify)
from ledger.HTTPError import HTTPError
import configparser
import os.path
import logging

log = logging.getLogger(__name__)
log.setLevel(logging.getLevelName('INFO'))
app = Flask(__name__)
config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '\\config.ini')
db = databasecontroller.get_database(config['database']['database_type'])


@app.route('/')
def hello_world():
    return 'Hello World'


@app.route('/info', methods=['GET'])
def site_info():
    log.info("Got a " + request.method + " for " + request.url + "from " + request.host_url)
    if request.method == 'GET':
        return jsonify({"response": "It worked!"})
    raise get_error_response(400, "Only GET requests are valid for this address")


@app.route('/login', methods=['POST'])
def login():
    log.info("Got a " + request.method + " for " + request.url + "from " + request.host_url)
    if request.method == 'POST':
        json_data = request.get_json()
        if json_data is not None:
            email = json_data.get('email')
            password = json_data.get('password')
            user_id = db.get_user_id(email, password)
            auth_token = db.get_user_auth_token(email, password)
            if (user_id is None) or (auth_token is None):
                raise get_error_response(403, "The email/password is invalid")
            response = jsonify({"user_id": user_id, "auth_token": auth_token})
            response.status_code = 200
            return response
        else:
            raise get_error_response(400, "Please include both the username and the password")
    else:
        raise get_error_response(400, "Only POST requests are valid for this address")


@app.route('/register', methods=['POST'])
def register():
    log.info("Got a " + request.method + " for " + request.url + "from " + request.host_url)
    if request.method == 'POST':
        json_data = request.get_json()
        if json_data is not None:
            email = json_data.get('email')
            password = json_data.get('password')
            name = json_data.get('name')
            db.add_user(email, password, name)
        else:
            raise get_error_response(400, "Please include the email, password, ")
    else:
        raise get_error_response(400, "Only POST requests are valid for this address")


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
