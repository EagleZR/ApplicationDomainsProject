from ledger import HTTPError
from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController
import logging
import os.path
import sqlite3
import hashlib
import secrets


class SQLITEDatabaseController(AbstractDatabaseController):
    database_file_name = os.path.dirname(os.path.realpath(__file__)) + '\\sqlitedb.db'

    def __init__(self):
        AbstractDatabaseController.__init__(self)
        if not os.path.isfile(self.database_file_name):
            logging.warning("The database did not exist, a new one is being created.")
        self.verify_tables_columns()

    def verify_tables_columns(self):
        # Make sure each table exists and possess the correct columns. If possible, add the tables.
        logging.info("Verifying database structure.")
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()
        try:
            cursor.execute('''SELECT * FROM Users''')
            logging.warning("User table already exists.")
        except sqlite3.OperationalError:
            logging.warning("Creating user table.")
            cursor.execute(
                '''Create Table If Not Exists Users(USER_ID integer primary key autoincrement, NAME TEXT not null, 
                EMAIL TEXT not null, PASSWORD_HASH TEXT not null, AUTH_TOKEN TEXT not null, ACCOUNT_TYPE Text not null 
                );''')
            db.commit()
            self.add_user("admin", "password2018", "admin")
            user_id, auth_token = self.get_login_data("admin", "password2018")
            self.set_account_type(user_id, "admin")

        cursor.close()
        db.close()
        # TODO Add tables as they're designed

    def add_user(self, email, password, name):
        logging.info("Adding user with email: " + email + ", password: " + password + ", name: " + name)
        try:
            if self.user_exists(email):
                raise DuplicateEmailException("A user with the email " + email + " already exists.")

            db = sqlite3.connect(self.database_file_name)
            cursor = db.cursor()
            parameter_dictionary = {"name": name, "email": email, "password_hash": hash_password(password),
                                    "auth_token": generate_auth_token(), "account_type": self.default_account_type}
            insert_text = '''Insert into Users (NAME, EMAIL, PASSWORD_HASH, AUTH_TOKEN, ACCOUNT_TYPE) values
                ('{name}', '{email}', '{password_hash}', '{auth_token}', '{account_type}');'''.format(
                **parameter_dictionary)
            cursor.execute(insert_text)
            db.commit()
            cursor.close()

            return self.user_exists(email)
        except sqlite3.OperationalError:
            return False

    def get_user_id(self, email, password):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select USER_ID from USERS where EMAIL = '%s' and PASSWORD_HASH = '%s' ''' % (
                email, hash_password(password)))
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            logging.error("Multiple results from get_user_id select statement. Results:")
            for result in results:
                logging.error(result)
        if len(results) is 0:
            return None
        return results[0]

    def get_user_auth_token(self, email, password):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select AUTH_TOKEN from USERS where EMAIL = '%s' and PASSWORD_HASH = '%s' ''' % (
                email, hash_password(password)))
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            logging.error("Multiple results from get_user_id select statement.")
        if len(results) is 0:
            return None
        return results[0]

    def user_exists(self, email):
        db = sqlite3.connect(self.database_file_name)
        check_cursor = db.cursor()

        parameter_dictionary = {"email": email}
        check_cursor.execute('''Select * from Users where EMAIL = '{email}';'''.format(**parameter_dictionary))
        response = check_cursor.fetchall()

        check_cursor.close()
        db.close()

        return len(response) > 0

    def get_login_data(self, email, password):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select USER_ID, AUTH_TOKEN from USERS where EMAIL = '%s' and PASSWORD_HASH = '%s' ''' % (
                email, hash_password(password)))
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            logging.error("Multiple results from get_user_id select statement.")
        if len(results) is 0:
            return None, None
        print(results[0])
        return results[0]

    def get_account_type(self, user_id):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select ACCOUNT_TYPE from USERS where USER_ID = '%s' ''' % user_id)
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            logging.error("Multiple results from get_user_id select statement.")
        if len(results) is 0:
            return None, None
        print(results[0])
        return results[0]

    def get_all_user_accounts(self):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute('''Select USER_ID, NAME, EMAIL, ACCOUNT_TYPE from USERS ''')

        results = list()
        results.extend(cursor.fetchall())
        if len(results) is 0:
            return None
        results_dict_list = list()
        for result in results:
            results_dict_list.append(
                {"user_id": result[0], "name": result[1], "email": result[2], "account_type": result[3]})
        return results_dict_list

    def set_account_type(self, user_id, account_type):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute('''UPDATE USERS SET ACCOUNT_TYPE = '%s' where USER_ID is '%s' ''' % (
            account_type, user_id))

        db.commit()
        cursor.close()
        
        return self.get_account_type(user_id) == account_type


class InvalidUserType(HTTPError):
    def __init__(self, message):
        Exception.__init__(self)
        self.message = message


class DuplicateEmailException(HTTPError):
    def __init__(self, message):
        Exception.__init__(self)
        self.message = message


def generate_auth_token():
    pass
    return secrets.token_urlsafe()


def hash_password(password):
    m = hashlib.sha256()
    m.update(password.encode())
    return str(m.hexdigest())
