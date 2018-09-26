from ledger.HTTPError import HTTPError
from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController
from datetime import datetime
import logging
import os.path
import sqlite3
import hashlib
import secrets


class SQLITEDatabaseController(AbstractDatabaseController):
    database_file_name = os.path.dirname(os.path.realpath(__file__)) + '/sqlitedb.db'

    def __init__(self):
        AbstractDatabaseController.__init__(self)
        if not os.path.isfile(self.database_file_name):
            logging.warning("The database did not exist, a new one is being created.")
        self.verify_tables_columns()

    def verify_tables_columns(self):
        # Make sure each table exists and possess the correct columns. If possible, add the tables.
        logging.info("Verifying database structure.")
        db = sqlite3.connect(self.database_file_name)
        user_cursor = db.cursor()
        try:
            user_cursor.execute('''SELECT * FROM Users''')
            logging.warning("User table already exists.")
        except sqlite3.OperationalError:
            logging.warning("Creating user table.")
            user_cursor.execute(
                '''Create Table If Not Exists Users(USER_ID integer primary key autoincrement, NAME TEXT not null, 
                USERNAME TEXT not null, PASSWORD_HASH TEXT not null, AUTH_TOKEN TEXT not null, ACCOUNT_TYPE Text not null,
                LAST_LOGIN TEXT, PASSWORD_EXPIRE_DATE TEXT NOT NULL);''')
            db.commit()
            if self.add_user("admin", "password2018", "admin", self.get_30_days_from_now()):
                logging.debug("Admin successfully created.")
            else:
                logging.error("Admin could not be created.")
            user_id = self.get_user_id("admin", "password2018")
            if not self.set_account_type(user_id, "admin"):
                logging.error("The database was not able to set the default admin's account type")
            else:
                logging.debug("The default admin was successfully initialized")
        user_cursor.close()

        forgot_password_cursor = db.cursor()
        try:
            forgot_password_cursor.execute('''SELECT * FROM FORGOTPASSWORD''')
            logging.warning("Forgot Password table already exists.")
        except sqlite3.OperationalError:
            logging.warning("Creating forgot password table")
            forgot_password_cursor.execute(
                '''Create Table if Not Exists FORGOTPASSWORD(USER_ID integer not null, SUBMISSIONDATE TEXT not null, 
                FOREIGN KEY (USER_ID) REFERENCES USERS(USER_ID));''')
            db.commit()
        forgot_password_cursor.close()

        db.close()
        # TODO Add tables as they're designed

    def add_user(self, username, password, name, password_expire_date):
        logging.info("Adding user with username: " + username + ", password: " + password + ", name: " + name)
        try:
            if self.user_exists(username):
                raise DuplicateUsernameException("A user with the username " + username + " already exists.")

            db = sqlite3.connect(self.database_file_name)
            cursor = db.cursor()
            parameter_dictionary = {"name": name, "username": username, "password_hash": hash_password(password),
                                    "auth_token": generate_auth_token(), "account_type": self.default_account_type,
                                    "expire_date": password_expire_date}
            insert_text = '''Insert into Users (NAME, USERNAME, PASSWORD_HASH, AUTH_TOKEN, ACCOUNT_TYPE, PASSWORD_EXPIRE_DATE) values
                ('{name}', '{username}', '{password_hash}', '{auth_token}', '{account_type}', '{expire_date}');'''.format(
                **parameter_dictionary)
            logging.debug(insert_text)
            cursor.execute(insert_text)
            db.commit()
            cursor.close()

            return self.user_exists(username)
        except sqlite3.OperationalError:
            return False

    def get_user_id(self, username=None, auth_token=None):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        if username is not None:
            cursor.execute(
                '''Select USER_ID from USERS where USERNAME = '%s' ''' % username)

        if auth_token is not None:
            command = '''Select USER_ID from USERS where AUTH_TOKEN = '%s' ''' % auth_token
            print(command)
            cursor.execute(command)
    
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            logging.error("Multiple results from get_user_id select statement. Results:" + str(results))
            for result in results:
                logging.error(result)
        if len(results) is 0:
            return None
        return results[0][0]

    def get_user_auth_token(self, username, password):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select AUTH_TOKEN from USERS where USERNAME = '%s' and PASSWORD_HASH = '%s' ''' % (
                username, hash_password(password)))
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            logging.error("Multiple results from get_user_auth_token select statement: " + str(results))
        if len(results) is 0:
            return None
        return results[0]

    def user_exists(self, username):
        db = sqlite3.connect(self.database_file_name)
        check_cursor = db.cursor()

        parameter_dictionary = {"username": username}
        check_cursor.execute('''Select * from Users where USERNAME = '{username}';'''.format(**parameter_dictionary))
        response = check_cursor.fetchall()

        check_cursor.close()
        db.close()

        return len(response) > 0

    def get_login_data(self, username, password):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select USER_ID, AUTH_TOKEN, LAST_LOGIN, PASSWORD_EXPIRE_DATE from USERS where USERNAME = '%s' and 
            PASSWORD_HASH = '%s' ''' % (
                username, hash_password(password)))
        results = list()
        results.extend(cursor.fetchall())
        logging.debug(results)
        if len(results) > 1:
            logging.error("Multiple results from get_login_data select statement: " + str(results))
        if len(results) is 0:
            logging.info("Invalid signin attempt")
            return None, None, None, None
        return results[0][:3] + (self.get_date(results[0][3]), )

    def get_account_type(self, user_id):
        return self.get_data("Users", "ACCOUNT_TYPE", "USER_ID", user_id)

    def get_all_user_accounts(self):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute('''Select USER_ID, NAME, USERNAME, ACCOUNT_TYPE from USERS ''')

        results = list()
        results.extend(cursor.fetchall())
        if len(results) is 0:
            return None
        results_dict_list = list()
        for result in results:
            results_dict_list.append(
                {"user_id": result[0], "name": result[1], "username": result[2], "account_type": result[3]})
        return results_dict_list

    def set_account_type(self, user_id, account_type):
        self.update_data("USERS", "ACCOUNT_TYPE", "USER_ID", user_id, account_type)
        return self.get_account_type(user_id) == account_type

    def update_password(self, user_id, new_password):
        self.update_data("USERS", "PASSWORD_HASH", "USER_ID", user_id, hash_password(new_password))
        return True  # TODO Verify update has occurred

    def update_last_login(self, user_id, last_login):
        self.update_data("USERS", "LAST_LOGIN", "USER_ID", user_id, self.get_date_string(last_login))
        return True  # TODO Verify update has occurred

    def set_password_expire(self, user_id, password_expire_date):
        self.update_data("USERS", "PASSWORD_EXPIRE_DATE", "USER_ID", user_id, password_expire_date)
        return True  # TODO Verify update has occurred

    def forgot_password(self, user_id):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()
        cursor.execute('''Insert into FORGOTPASSWORD (USER_ID, SUBMISSIONDATE) values (%s, %s)''' % (
            user_id, self.get_date_string(datetime.today())))

    def get_forgotten_passwords(self):
        return self.get_data("FORGOTPASSWORD", "USER_ID")

    def update_data(self, table, field, identifier_type, identifier, data):
        """Updates data in a given table and given column (field) where the data in the identifier_type column matches
        the given identifier

        :param table: The table whose data will be edited
        :param field: The field (column) of the data to be edited
        :param identifier_type: The name of the column which will be used as the identifier
        :param identifier: The identifier used to select the correct line whose data will be edited
        :param data: The data to be updated
        """
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        logging.debug(
            '''UPDATE %s SET %s = '%s' where %s is '%s' ''' % (table, field, data, identifier_type, identifier))

        cursor.execute('''UPDATE %s SET %s = '%s' where %s is '%s' ''' % (
            table, field, data, identifier_type, identifier))

        db.commit()
        cursor.close()

    def get_data(self, table, field, identifier_type=None, identifier=None):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        if identifier_type is None:
            cursor.execute('''Select %s from %s where %s = '%s' ''' % (field, table, identifier_type, identifier))
        else:
            cursor.execute('''Select %s from %s ''' % (field, table))
        results = list()
        results.extend(cursor.fetchall())
        if len(results) > 1:
            logging.error("Multiple results from get_user_id select statement.")
        if len(results) is 0:
            return None
        return results

    # def get_data(self, table, field_list, identifier_type_list, identifier_list):
    #     field_string = ""
    #     for i in range(0, len(field_list)):
    #         field_string += field_list[i] + ", "
    #     field_string = field_string.

    def verify_user(self, auth_token, user_id):
        logging.debug("Verifying user " + str(user_id) if user_id is not None else "None" + " with auth_token " +
                                                                                   auth_token if auth_token is not None else "None")

        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''SELECT USERNAME FROM USERS WHERE AUTH_TOKEN is '%s' and USER_ID is '%s' ''' % (auth_token, user_id))

        results = cursor.fetchall()
        logging.debug("There are " + str(len(results)) + " who match this verification information")
        return len(results) == 1


class InvalidUserType(HTTPError):
    def __init__(self, message):
        super(HTTPError, self).__init__(self, message)


class DuplicateUsernameException(HTTPError):
    def __init__(self, message):
        super(HTTPError, self).__init__(self, message)


def generate_auth_token():
    pass
    return secrets.token_urlsafe()


def hash_password(password):
    m = hashlib.sha256()
    m.update(password.encode())
    return str(m.hexdigest())
