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
        self.db = sqlite3.connect(database_file_name)
        self.verify_tables_columns()

    def verify_tables_columns(self):
        # Make sure each table exists and possess the correct columns. If possible, add the tables.
        self.log.info("Verifying database structure.")
        cursor = self.db.cursor()
        try:
            cursor.execute('''SELECT * FROM Users''')
            cursor.close()
            self.log.warning("User table already exists.")
        except sqlite3.OperationalError:
            self.log.warning("Creating user table.")
            cursor.execute(
                '''Create Table Users(USER_ID integer primary key autoincrement, USERNAME varchar(40) not null, 
                PASSWORD_HASH varchar(100) not null, AUTH_TOKEN varchar(100) not null, ACCOUNT_TYPE varchar(10) 
                not null )''')
            print('''Insert into Users(USERNAME, PASSWORD_HASH, AUTH_TOKEN, ACCOUNT_TYPE) values (%s, %s, %s, %s)''' %
                  ("u32ser", "asdkjhasdkjh", get_auth_token(), "user"))
            cursor.execute(
                '''Insert into Users(USERNAME, PASSWORD_HASH, AUTH_TOKEN, ACCOUNT_TYPE) values (%s, %s, %s, %s)''' %
                ("u32ser", "asdkjhasdkjh", get_auth_token(), "user"))
            cursor.execute('''SELECT * FROM Users''')
            self.db.commit()
        # TODO Add tables as they're designed

    def add_user(self, username, password_hash, account_type="deactivated"):
        if account_type not in self.account_types:
            raise InvalidUserType("The user type " + account_type + " is not an approved account type")
        cursor = self.db.cursor()
        cursor.execute(
            '''Insert into Users (USERNAME, PASSWORD_HASH, AUTH_TOKEN, ACCOUNT_TYPE) values (%s, %s, %s, %s)''' %
            (username, password_hash, get_auth_token(), account_type))
        cursor.close()
        self.db.commit()

    def get_user_id(self, username, password_hash):
        cursor = self.db.cursor()
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
        cursor = self.db.cursor()
        cursor.execute(
            '''Select AUTH_TOKEN from USERS where USERNAME = '?' and PASSWORD_HASH = '?' ''', (username, password_hash))
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            self.log.error("Multiple results from get_user_id select statement.")
        if len(results) is 0:
            return None
        return results[0]

    def close(self):
        self.db.close()


class InvalidUserType(Exception):
    def __init__(self, message):
        Exception.__init__(message)


def get_auth_token():
    return "Auth_token"  # TODO Make this actually real
