from postit.HTTPError import HTTPError
from postit.databasecontroller.AbstractDatabaseController import AbstractDatabaseController
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

        # User Table
        user_cursor = db.cursor()
        try:
            user_cursor.execute('''SELECT * FROM Users''')
            logging.debug("User table already exists.")
        except sqlite3.OperationalError:
            logging.warning("Creating user table.")
            user_cursor.execute(
                '''Create Table If Not Exists Users(USER_ID integer primary key autoincrement, FIRST_NAME TEXT not null, 
                LAST_NAME TEXT not null, USERNAME TEXT not null, EMAIL TEXT not null, PASSWORD_HASH TEXT not null, 
                AUTH_TOKEN TEXT not null, ACCOUNT_TYPE Text not null, LAST_LOGIN TEXT, 
                PASSWORD_EXPIRE_DATE TEXT NOT NULL);''')
            db.commit()
            if self.add_user("admin", "password2018", "admin@markzeagler.com", "Mark", "Zeagler",
                             self.get_30_days_from_now()):
                logging.debug("Admin successfully created.")
            else:
                logging.error("Admin could not be created.")
            user_id = self.get_user_id("admin")
            if not self.set_user_type(user_id, "admin"):
                logging.error("The database was not able to set the default admin's account type")
            else:
                logging.debug("The default admin was successfully initialized")
        user_cursor.close()

        # Forgot Password Table
        forgot_password_cursor = db.cursor()
        try:
            forgot_password_cursor.execute('''SELECT * FROM FORGOTPASSWORD''')
            logging.debug("Forgot Password table already exists.")
        except sqlite3.OperationalError:
            logging.warning("Creating forgot password table")
            forgot_password_cursor.execute(
                '''Create Table if Not Exists FORGOTPASSWORD(USER_ID integer not null, SUBMISSIONDATE TEXT not null, 
                FOREIGN KEY (USER_ID) REFERENCES USERS(USER_ID));''')
            db.commit()
        forgot_password_cursor.close()

        # Table of Accounts
        accounts_cursor = db.cursor()
        try:
            accounts_cursor.execute('''SELECT * FROM ACCOUNTS''')
            logging.debug("Table of Accounts already exists.")
        except sqlite3.OperationalError:
            logging.warning("Creating Table of Accounts")
            accounts_cursor.execute(
                '''Create Table if Not Exists ACCOUNTS(ACCOUNT_ID integer not null, ACCOUNT_TITLE TEXT not null, 
                NORMAL_SIDE TEXT not null, DESCRIPTION TEXT, IS_ACTIVE TEXT not null, BALANCE NUMBER not null, 
                DATE_CREATED TEXT not null, CREATED_BY INTEGER not null, LAST_EDITED_DATE TEXT not null, 
                LAST_EDITED_BY INTEGER, FOREIGN KEY (CREATED_BY) REFERENCES USERS(USER_ID), FOREIGN KEY (LAST_EDITED_BY) 
                REFERENCES USERS(USER_ID));''')
            db.commit()
        accounts_cursor.close()

        # User-Account Access Table
        user_account_cursor = db.cursor()
        try:
            user_account_cursor.execute('''SELECT * FROM USER_ACCOUNT_ACCESS''')
            logging.debug("User-Account Access table already exists")
        except sqlite3.OperationalError:
            logging.warning("Creating User-Account Access table")
            user_account_cursor.execute(
                '''Create Table if Not Exists USER_ACCOUNT_ACCESS(ACCOUNT_ID integer not null, USER_ID integer not 
                null, FOREIGN KEY (ACCOUNT_ID) REFERENCES ACCOUNTS(ACCOUNT_ID), FOREIGN KEY (USER_ID) REFERENCES 
                USERS(USER_ID));''')
            db.commit()
        user_account_cursor.close()

        # TODO Add tables as they're designed
        db.close()

    def add_user(self, username, password, email, first_name, last_name, password_expire_date):
        logging.info(
            "Adding user with username: " + username + ", password: " + password + ", name: " + first_name + " " +
            last_name + ", email: " + email)
        try:
            if self.user_exists(username):
                raise DuplicateIDException("username", username)

            db = sqlite3.connect(self.database_file_name)
            cursor = db.cursor()
            parameter_dictionary = {"first_name": first_name, "last_name": last_name, "username": username,
                                    "email": email, "password_hash": hash_password(password),
                                    "auth_token": generate_auth_token(), "account_type": self.default_account_type,
                                    "expire_date": password_expire_date}
            insert_text = '''Insert into Users (FIRST_NAME, LAST_NAME, USERNAME, EMAIL, PASSWORD_HASH, AUTH_TOKEN, 
            ACCOUNT_TYPE, PASSWORD_EXPIRE_DATE) values('{first_name}', '{last_name}', '{username}', '{email}', 
            '{password_hash}', '{auth_token}', '{account_type}', '{expire_date}');'''.format(
                **parameter_dictionary)
            logging.debug(insert_text)
            cursor.execute(insert_text)
            db.commit()
            cursor.close()

            return self.user_exists(username)
        except sqlite3.OperationalError:
            return False

    def add_account(self, account_id, account_title, normal_side, description, created_by):
        logging.info(
            "Adding account with account_id: " + account_id + ", account_title: " + account_title + ", normal_side: "
            + normal_side + ", description: \"" + description + "\"")
        check_exists = self.get_account(account_id)
        if check_exists is not None and len(check_exists) > 0:
            raise DuplicateIDException("account_id", account_id)

        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()
        insert_text = '''Insert into ACCOUNTS (ACCOUNT_ID, ACCOUNT_TITLE, NORMAL_SIDE, DESCRIPTION, IS_ACTIVE, BALANCE, 
        DATE_CREATED, CREATED_BY, LAST_EDITED_DATE) values ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');''' \
                      % (account_id, account_title, normal_side, description, "TRUE", 0,
                         datetime.today().strftime(self.date_string_format), created_by,
                         datetime.today().strftime(self.date_string_format))
        logging.debug(insert_text)
        cursor.execute(insert_text)
        db.commit()
        cursor.close()

        return len(self.get_account(account_id)) == 1

    def get_user_id(self, username=None, auth_token=None):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        if username is not None:
            cursor.execute(
                '''Select USER_ID from USERS where USERNAME = '%s' ''' % username)

        if auth_token is not None:
            command = '''Select USER_ID from USERS where AUTH_TOKEN = '%s' ''' % auth_token
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
            PASSWORD_HASH = '%s' ''' % (username, hash_password(password)))
        results = list()
        results.extend(cursor.fetchall())
        logging.debug(results)
        if len(results) > 1:
            logging.error("Multiple results from get_login_data select statement: " + str(results))
        if len(results) is 0:
            logging.info("Invalid signin attempt")
            return None, None, None, None
        return results[0][:3] + (self.get_date(results[0][3]),)

    def get_user_type(self, user_id):
        results = self.get_data("Users", "ACCOUNT_TYPE", "USER_ID", user_id)
        if results is None:
            logging.debug("No results from get_account_type were returned")
            return None
        if len(results) > 1:
            logging.debug("Multiple results from get_account_type select statement: " + str(results))
        return results[0][0]

    def get_all_user_accounts(self):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select USER_ID, USERNAME, FIRST_NAME, LAST_NAME, EMAIL, ACCOUNT_TYPE, LAST_LOGIN, 
            PASSWORD_EXPIRE_DATE from USERS ''')

        results = list()
        results.extend(cursor.fetchall())
        if len(results) is 0:
            return None
        results_dict_list = list()
        for result in results:
            results_dict_list.append(
                {"user_id": result[0], "username": result[1], "first_name": result[2], "last_name": result[3],
                 "email": result[4], "user_type": result[5], "last_login": result[6],
                 "password_expiration_date": result[7]})
        return results_dict_list

    def set_user_type(self, user_id, account_type):
        if account_type not in self.account_types:
            raise InvalidUserType(account_type, self.account_types)
        self.update_data("USERS", "ACCOUNT_TYPE", "USER_ID", user_id, account_type)
        return self.get_user_type(user_id) == account_type

    def update_password(self, user_id, new_password):
        self.update_data("USERS", "PASSWORD_HASH", "USER_ID", user_id, hash_password(new_password))
        self.remove_data("FORGOTPASSWORD", "USER_ID", user_id)
        return hash_password(new_password) == self.get_data("USERS", "PASSWORD_HASH", "USER_ID", user_id)

    def update_last_login(self, user_id, last_login):
        self.update_data("USERS", "LAST_LOGIN", "USER_ID", user_id, self.get_date_string(last_login))
        return True  # TODO Verify update has occurred

    def set_password_expire(self, user_id, password_expire_date):
        self.update_data("USERS", "PASSWORD_EXPIRE_DATE", "USER_ID", user_id, password_expire_date)
        return True  # TODO Verify update has occurred

    def forgot_password(self, user_id):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()
        command = '''Insert into FORGOTPASSWORD (USER_ID, SUBMISSIONDATE) values ('%s', '%s')''' % (
            user_id, self.get_date_string(datetime.today()))
        logging.debug(command)
        cursor.execute(command)
        db.commit()
        cursor.close()
        db.close()

    def get_forgotten_passwords(self):
        return self.get_data("FORGOTPASSWORD", "*")

    def get_username(self, user_id):
        usernames = self.get_data("USERS", "USERNAME", "USER_ID", user_id)
        if len(usernames) > 1:
            logging.error("Multiple usernames were returned for the user_id: " + user_id)
            logging.error("Usernames: " + str(usernames))
        if len(usernames) == 0:
            logging.debug("No usernames are associated with the user_id: " + user_id)
            return None
        return usernames[0][0]

    def get_last_login(self, user_id):
        return self.get_data("USERS", "LAST_LOGIN", "USER_ID", user_id)

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
        db.close()

    def get_data(self, table, field="*", identifier_type=None, identifier=None):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        if identifier_type is not None:
            command = '''Select %s from %s where %s is '%s' ''' % (field, table, identifier_type, identifier)
            logging.debug(command)
            cursor.execute(command)
        else:
            command = '''Select %s from %s ''' % (field, table)
            logging.debug(command)
            cursor.execute(command)

        results = list()
        results.extend(cursor.fetchall())
        logging.debug(str(results))
        if len(results) > 1:
            logging.debug("Multiple results from get_data select statement: " + str(results))
        if len(results) is 0:
            return None
        return results

    def remove_data(self, table, identifier_type, identifier):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        command = '''DELETE FROM %s where %s is '%s' ''' % (table, identifier_type, identifier)
        logging.debug(command)
        cursor.execute(command)

        db.commit()
        cursor.close()
        db.close()

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

    def get_user_has_account_access(self, user_id, account_id):
        account_type = self.get_user_type(user_id)
        if account_type == 'admin':
            return True
        if account_type == 'manager':  # Keeping these separate because these authorizations might change
            return True

        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        command = '''Select * from USER_ACCOUNT_ACCESS where USER_ID is '%s' and ACCOUNT_ID is '%s' ''' % (
            user_id, account_id)
        logging.debug(command)
        cursor.execute(command)

        results = list()
        results.extend(cursor.fetchall())
        logging.debug(str(results))

        if results is None or len(results) is 0:
            return False
        else:
            return True

    def set_user_account_access(self, user_id, account_id, can_access):
        if can_access:
            if self.get_user_has_account_access(user_id, account_id):
                return True  # Do nothing, already has access
            else:
                db = sqlite3.connect(self.database_file_name)
                cursor = db.cursor()

                command = '''Insert into USER_ACCOUNT_ACCESS (USER_ID, ACCOUNT_ID) values ('%s', '%s')''' % (
                    user_id, account_id)
                logging.debug(command)
                cursor.execute(command)
                db.commit()
                cursor.close()
                db.close()
                return self.get_user_has_account_access(user_id, account_id)
        else:
            if not self.get_user_has_account_access(user_id, account_id):
                return True  # Do nothing, already doesn't have access
            else:
                db = sqlite3.connect(self.database_file_name)
                cursor = db.cursor()

                command = '''DELETE FROM USER_ACCOUNT_ACCESS where USER_ID is '%s' and ACCOUNT_ID is '%s' ''' % \
                          (user_id, account_id)
                logging.debug(command)

                cursor.execute(command)
                db.commit()
                cursor.close()
                db.close()
                return not self.get_user_has_account_access(user_id, account_id)

    def get_accounts(self):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select ACCOUNT_ID, ACCOUNT_TITLE, NORMAL_SIDE, BALANCE, DATE_CREATED, CREATED_BY, LAST_EDITED_DATE, 
            LAST_EDITED_BY, DESCRIPTION, IS_ACTIVE from ACCOUNTS''')

        results = list()
        results.extend(cursor.fetchall())

        db.commit()
        cursor.close()
        db.close()

        if len(results) is 0:
            return None

        results_dict_list = list()
        for result in results:
            results_dict_list.append(
                {"account_id": result[0], "account_title": result[1], "normal_side": result[2], "balance": result[3],
                 "date_created": result[4], "created_by": result[5], "last_edited_date": result[6],
                 "last_edited_by": result[7], "description": result[8], "is_active": result[9]})
        return results_dict_list

    def get_viewable_accounts(self, user_id):
        user_type = self.get_user_type(user_id)
        if user_type == 'admin':
            return self.get_accounts()
        if user_type == 'manager':  # Keeping these separate because these authorizations might change
            return self.get_accounts()

        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        command = '''Select ACCOUNT_ID, ACCOUNT_TITLE, NORMAL_SIDE, BALANCE, DATE_CREATED, CREATED_BY, LAST_EDITED_DATE, 
            LAST_EDITED_BY, DESCRIPTION, IS_ACTIVE From ACCOUNTS where ACCOUNT.ACCOUNT_ID in 
            (SELECT ACCOUNT_ID FROM USER_ACCOUNT_ACCESS where USER_ID is %s)''' % user_id
        logging.debug(command)

        cursor.execute(command)
        results = list()
        results.extend(cursor.fetchall())
        logging.debug(str(results))

        db.commit()
        cursor.close()
        db.close()

        results_dict_list = list()
        for result in results:
            results_dict_list.append(
                {"account_id": result[0], "account_title": result[1], "normal_side": result[2], "balance": result[3],
                 "date_created": result[4], "created_by": result[5], "last_edited_date": result[6],
                 "last_edited_by": result[7], "description": result[8], "is_active": result[9]})
        return results_dict_list

    def get_account(self, account_id):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        command = '''Select ACCOUNT_ID, ACCOUNT_TITLE, NORMAL_SIDE, BALANCE, DATE_CREATED, CREATED_BY, LAST_EDITED_DATE, 
                    LAST_EDITED_BY, DESCRIPTION, IS_ACTIVE From ACCOUNTS where ACCOUNT_ID is %s''' % account_id
        logging.debug(command)

        cursor.execute(command)
        results = list()
        results.extend(cursor.fetchall())
        logging.debug(str(results))

        db.commit()
        cursor.close()
        db.close()

        results_dict_list = list()
        for result in results:
            results_dict_list.append(
                {"account_id": result[0], "account_title": result[1], "normal_side": result[2], "balance": result[3],
                 "date_created": result[4], "created_by": result[5], "last_edited_date": result[6],
                 "last_edited_by": result[7], "description": result[8], "is_active": result[9]})
        return results_dict_list

    def get_table(self, table_name):
        return self.get_data(table_name)

    def get_user(self, user_id):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select USER_ID, USERNAME, FIRST_NAME, LAST_NAME, EMAIL, ACCOUNT_TYPE, LAST_LOGIN, 
            PASSWORD_EXPIRE_DATE from USERS where USER_ID is %s''' % user_id)

        results = list()
        results.extend(cursor.fetchall())
        if len(results) is 0:
            return None

        result = {"user_id": results[0][0], "username": results[0][1], "first_name": results[0][2], "last_name": results[0][3],
         "email": results[0][4], "user_type": results[0][5], "last_login": results[0][6],
         "password_expiration_date": results[0][7]}

        return result

    def set_user_data(self, user_id, category, value):
        self.update_data("USERS", category, "USER_ID", user_id, value)
        return value == self.get_data("USERS", category, "USER_ID", user_id)


class InvalidUserType(HTTPError):
    def __init__(self, user_type, account_types):
        HTTPError.__init__(self,
                           "Invalid user type: " + user_type + ". Not in list of acceptable account types: " + str(
                               account_types))


class DuplicateIDException(HTTPError):
    def __init__(self, id_type, identifier):
        HTTPError.__init__(self, "A user with the " + id_type + " " + identifier + " already exists.")


def generate_auth_token():
    pass
    return secrets.token_urlsafe()


def hash_password(password):
    m = hashlib.sha256()
    m.update(password.encode())
    return str(m.hexdigest())
