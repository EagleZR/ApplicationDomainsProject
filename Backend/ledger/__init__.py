from ledger.HTTPError import HTTPError
from ledger.databasecontroller.DummyDatabaseController import DummyDatabaseController
from flask import (Flask, request, jsonify)
import logging

app = Flask(__name__)
db = DummyDatabaseController()


@app.route('/')
def hello_world():
    return 'Hello World'


@app.route('/info', methods=['GET'])
def site_info():
    logging.info("Got a " + request.method + " for " + request.url + "from " + request.host_url)
    if request.method == 'GET':
        return jsonify({"response": "It worked!"})
    raise get_error_response(400, "Only GET requests are valid for this address")


@app.route('/login', methods=['POST'])
def login():
    logging.info("Got a " + request.method + " for " + request.url + "from " + request.host_url)
    if request.method == 'POST':
        json_data = request.get_json()
        if json_data is not None:
            username = json_data.get('username')
            password_hash = json_data.get('password_hash')
            user_id = db.get_user_id(username, password_hash)
            auth_token = db.get_user_auth_token(username, password_hash)
            if (user_id is None) or (auth_token is None):
                raise get_error_response(403, "The username/password is invalid")
            response = jsonify({"user_id": user_id, "auth_token": auth_token})
            response.status_code = 200
            return response
        else:
            raise get_error_response(400, "Please include both the username and the password")
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
    app.run(host='markzeagler.com', debug=True)
