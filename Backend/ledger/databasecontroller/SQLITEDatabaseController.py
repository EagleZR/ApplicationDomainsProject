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
        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.getLevelName('INFO'))
        if not os.path.isfile(self.database_file_name):
            self.log.warning("The database did not exist, a new one is being created.")
        self.verify_tables_columns()

    def verify_tables_columns(self):
        # Make sure each table exists and possess the correct columns. If possible, add the tables.
        self.log.info("Verifying database structure.")
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()
        try:
            cursor.execute('''SELECT * FROM Users''')
            self.log.warning("User table already exists.")
        except sqlite3.OperationalError:
            self.log.warning("Creating user table.")
            cursor.execute(
                '''Create Table If Not Exists Users(USER_ID integer primary key autoincrement, NAME TEXT not null, 
                EMAIL TEXT not null, PASSWORD_HASH TEXT not null, AUTH_TOKEN TEXT not null, ACCOUNT_TYPE Text not null 
                );''')
            db.commit()
        cursor.close()
        db.close()
        # TODO Add tables as they're designed

    def add_user(self, email, password, name):
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

            if self.user_exists(email):
                return True
            return False
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
            self.log.error("Multiple results from get_user_id select statement. Results:")
            for result in results:
                self.log.error(result)
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
            self.log.error("Multiple results from get_user_id select statement.")
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

        num = len(response)
        if num > 0:
            return True
        return False


class InvalidUserType(Exception):
    def __init__(self, message):
        Exception.__init__(self)
        self.message = message


class DuplicateEmailException(Exception):
    def __init__(self, message):
        Exception.__init__(self)
        self.message = message


def generate_auth_token():
    return secrets.token_urlsafe()


def hash_password(password):
    m = hashlib.sha256()
    m.update(password.encode())
    return str(m.hexdigest())
