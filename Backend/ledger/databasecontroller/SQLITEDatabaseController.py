from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController
import logging
import os.path
import sqlite3
import hashlib
import secrets

database_file_name = os.path.dirname(os.path.realpath(__file__)) + '\\sqlitedb.db'


class SQLITEDatabaseController(AbstractDatabaseController):
    def __init__(self):
        AbstractDatabaseController.__init__(self)
        self.log = logging.getLogger(__name__)
        self.log.setLevel(logging.getLevelName('INFO'))
        if not os.path.isfile(database_file_name):
            self.log.warning("The database did not exist, a new one is being created.")
        self.verify_tables_columns()

    def verify_tables_columns(self):
        # Make sure each table exists and possess the correct columns. If possible, add the tables.
        self.log.info("Verifying database structure.")
        db = sqlite3.connect(database_file_name)
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
            db = sqlite3.connect(database_file_name)
            check_cursor = db.cursor()

            check_cursor.execute('''Select * from Users where EMAIL = '%s';''' % (email,))
            num = len(check_cursor.fetchall())
            if num > 0:
                raise DuplicateEmailException("A user with the email " + email + " already exists.")
            check_cursor.close()

            cursor = db.cursor()

            dictionary = {"name": name, "email": email, "password_hash": hash_password(password),
                          "auth_token": get_auth_token(), "account_type": self.default_account_type}
            insert_text = '''Insert into Users (NAME, EMAIL, PASSWORD, AUTH_TOKEN, ACCOUNT_TYPE) values
                ('{name}', '{email}', '{password_hash}', '{auth_token}', '{account_type}');'''.format(**dictionary)
            cursor.execute(insert_text)
            db.commit()
            cursor.close()
            db.close()
            return True
        except sqlite3.OperationalError:
            return False

    def get_user_id(self, email, password):
        db = sqlite3.connect(database_file_name)
        cursor = db.cursor()

        print(hash_password(password))

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
        db = sqlite3.connect(database_file_name)
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


class InvalidUserType(Exception):
    def __init__(self, message):
        Exception.__init__(message)


class DuplicateEmailException(Exception):
    def __init__(self, message):
        Exception.__init__(message)


def get_auth_token():
    return secrets.token_urlsafe()


def hash_password(password):
    m = hashlib.sha256()
    m.update(password.encode())
    return str(m.hexdigest())
