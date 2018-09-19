from ledger.HTTPError import HTTPError
from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController
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
            if not self.set_account_type(user_id, "admin"):
                logging.error("The database was not able to set the default admin's account type")
            else:
                logging.info("The default admin was successfully initialized")

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

    def get_user_id(self, email=None, password=None, auth_token=None):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        if email is not None and password is not None:
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
            return results[0][0]

        if auth_token is not None:
            cursor.execute(
                '''Select USER_ID from USERS where AUTH_TOKEN = '%s' ''' % (auth_token))
            results = list()
            results.extend(cursor.fetchall())
            if len(results) > 1:
                logging.error("Multiple results from get_user_id select statement. Results:")
                for result in results:
                    logging.error(result)
            if len(results) is 0:
                return None
            return results[0][0]

        raise HTTPError(500, "A get_user_id request was sent to the database without email, password, or auth_token")

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
        return results[0][0]

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
        self.update_data("USERS", "ACCOUNT_TYPE", "USER_ID", user_id, account_type)

        return self.get_account_type(user_id) == account_type

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
            '''SELECT EMAIL FROM USERS WHERE AUTH_TOKEN is '%s' and USER_ID is '%s' ''' % (auth_token, user_id))

        results = cursor.fetchall()
        logging.debug("There are " + str(len(results)) + " who match this verification information")
        return len(results) == 1


class InvalidUserType(HTTPError):
    def __init__(self, message):
        super(HTTPError, self).__init__(self, message)


class DuplicateEmailException(HTTPError):
    def __init__(self, message):
        super(HTTPError, self).__init__(self, message)


def generate_auth_token():
    pass
    return secrets.token_urlsafe()


def hash_password(password):
    m = hashlib.sha256()
    m.update(password.encode())
    return str(m.hexdigest())
