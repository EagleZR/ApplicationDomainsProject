from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController
import logging
import os.path
import sqlite3

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
                '''Create Table If Not Exists Users(USER_ID integer primary key autoincrement, USERNAME TEXT not null, 
                PASSWORD_HASH TEXT not null, AUTH_TOKEN TEXT not null, ACCOUNT_TYPE Text not null );''')
            # print('''Insert into Users(USERNAME, PASSWORD_HASH, AUTH_TOKEN, ACCOUNT_TYPE) values (%s, %s, %s, %s);''' %
            #       ("u32ser", "asdkjhasdkjh", get_auth_token(), "user"))
            # cursor.execute(
            #     '''Insert into Users(USERNAME, PASSWORD_HASH, AUTH_TOKEN, ACCOUNT_TYPE) values (%s, %s, %s, %s);''' %
            #     ("u32ser", "asdkjhasdkjh", get_auth_token(), "user"))
            # cursor.execute('''SELECT * FROM Users;''')
            db.commit()
        cursor.close()
        db.close()
        # TODO Add tables as they're designed

    def add_user(self, username, password_hash):
        try:
            account_type = "pending"
            db = sqlite3.connect(database_file_name)
            cursor = db.cursor()
            dictionary = {"username": username, "password_hash": password_hash, "auth_token": get_auth_token(),
                          "account_type": account_type}
            insert_text = '''Insert into Users (USERNAME, PASSWORD_HASH, AUTH_TOKEN, ACCOUNT_TYPE) values
                ('{username}', '{password_hash}', '{auth_token}', '{account_type}');'''.format(**dictionary)
            cursor.execute(insert_text)
            db.commit()
            cursor.close()
            db.close()
            return True
        except sqlite3.OperationalError:
            return False

    def get_user_id(self, username, password_hash):
        db = sqlite3.connect(database_file_name)
        cursor = db.cursor()
        cursor.execute(
            '''Select USER_ID from USERS where USERNAME = '%s' and PASSWORD_HASH = '%s' ''' % (username, password_hash))
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            self.log.error("Multiple results from get_user_id select statement. Results:")
            for result in results:
                self.log.error(result)
        if len(results) is 0:
            return None
        return results[0]

    def get_user_auth_token(self, username, password_hash):
        db = sqlite3.connect(database_file_name)
        cursor = db.cursor()
        cursor.execute(
            '''Select AUTH_TOKEN from USERS where USERNAME = '?' and PASSWORD_HASH = '?' ''', (username, password_hash))
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


def get_auth_token():
    return "Auth_token"  # TODO Make this actually real
