from postit.PostitHTTPError import PostitHTTPError
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
            from datetime import timedelta
            if self.add_user("admin", "password2018", "admin@markzeagler.com", "root", "admin",
                             (datetime.today() + timedelta(days=100000)).strftime(
                                 self.date_string_format)):
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
                NORMAL_SIDE TEXT not null, DESCRIPTION TEXT, IS_ACTIVE TEXT not null, DATE_CREATED TEXT not null, 
                CREATED_BY INTEGER not null, LAST_EDITED_DATE TEXT not null, CATEGORY TEXT not null, 
                SUBCATEGORY TEXT not null, LAST_EDITED_BY INTEGER, FOREIGN KEY (CREATED_BY) REFERENCES USERS(USER_ID), 
                FOREIGN KEY (LAST_EDITED_BY) REFERENCES USERS(USER_ID));''')
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

        # Journal Entry Table
        journal_cursor = db.cursor()
        try:
            journal_cursor.execute('''SELECT * FROM JOURNAL_ENTRIES''')
            logging.debug("Journal Entry table already exists")
        except sqlite3.OperationalError:
            logging.warning("Creating Journal Entry table")
            journal_cursor.execute(
                '''Create Table if Not Exists JOURNAL_ENTRIES(JOURNAL_ENTRY_ID integer primary key autoincrement, USER_ID integer not 
                null, DATE text not null, DESCRIPTION text, TYPE text not null, STATUS text not null, 
                POSTING_REFERENCE integer, POSTING_MANAGER integer, FOREIGN KEY (USER_ID) REFERENCES USERS(USER_ID), 
                FOREIGN KEY (POSTING_MANAGER) REFERENCES USERS(USER_ID));''')
            db.commit()
        journal_cursor.close()

        # Transactions Table
        transaction_cursor = db.cursor()
        try:
            transaction_cursor.execute('''SELECT * FROM TRANSACTIONS''')
            logging.debug("Transactions table already exists")
        except sqlite3.OperationalError:
            logging.warning("Creating Transactions table")
            transaction_cursor.execute(
                '''Create Table if Not Exists TRANSACTIONS(TRANSACTION_ID integer primary key autoincrement, JOURNAL_ENTRY_ID 
    integer not null, ACCOUNT_ID integer not null, AMOUNT real not null,  FOREIGN KEY (JOURNAL_ENTRY_ID) REFERENCES JOURNAL_ENTRIES(JOURNAL_ENTRY_ID), 
     FOREIGN KEY (ACCOUNT_ID) REFERENCES ACCOUNTS(ACCOUNT_ID));''')
            db.commit()
        transaction_cursor.close()

        # # Posting Table
        # posting_cursor = db.cursor()
        # try:
        #     posting_cursor.execute('''SELECT * FROM POSTINGS''')
        #     logging.debug("Postings Table already exists")
        # except sqlite3.OperationalError:
        #     logging.warning("Creating Postings Table")
        #     posting_cursor.execute('''Create Table if Not Exists POSTINGS(POSTING_REFERENCE integer primary key autoincrement,
        #     JOURNAL_ENTRY_ID integer not null, POSTING_MANAGER integer not null, POSTING_DATE text not null,
        #     FOREIGN KEY (POSTING_MANAGER) REFERENCES USERS(USER_ID), FOREIGN KEY (JOURNAL_ENTRY_ID) REFERENCES
        #     JOURNAL_ENTRIES(JOURNAL_ENTRY_ID))''')
        #     db.commit()
        # transaction_cursor.close()

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
            parameters = (first_name, last_name, username, email, hash_password(password),
                          generate_auth_token(), self.default_account_type, password_expire_date)
            cursor.execute('''Insert into Users (FIRST_NAME, LAST_NAME, USERNAME, EMAIL, PASSWORD_HASH, AUTH_TOKEN, 
            ACCOUNT_TYPE, PASSWORD_EXPIRE_DATE) values(?, ?, ?, ?, ?, ?, ?, ?);''', parameters)
            db.commit()
            cursor.close()

            return self.user_exists(username)
        except sqlite3.OperationalError:
            return False

    def add_account(self, account_id, account_title, normal_side, description, category, subcategory, created_by):
        logging.info(
            "Adding account with account_id: " + account_id + ", account_title: " + account_title + ", normal_side: "
            + normal_side + ", description: \"" + description + "\"")
        try:
            check_exists = self.get_account(account_id)
            if check_exists is not None and len(check_exists) > 0:
                raise DuplicateIDException("account_id", account_id)
        except sqlite3.OperationalError:
            pass

        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()
        cursor.execute('''Insert into ACCOUNTS (ACCOUNT_ID, ACCOUNT_TITLE, NORMAL_SIDE, DESCRIPTION, IS_ACTIVE,  
        DATE_CREATED, CREATED_BY, LAST_EDITED_DATE, CATEGORY, SUBCATEGORY) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);''',
                       (account_id, account_title, normal_side, description, "Y",
                        datetime.today().strftime(self.date_string_format), created_by,
                        datetime.today().strftime(self.date_string_format), category, subcategory))
        db.commit()
        cursor.close()

        return len(self.get_account(account_id)) == 1

    def get_user_id(self, username=None, auth_token=None):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        if username is not None:
            cursor.execute(
                '''Select USER_ID from USERS where USERNAME = ?''', (username,))

        if auth_token is not None:
            cursor.execute('''Select USER_ID from USERS where AUTH_TOKEN = ? ''', (auth_token,))

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
            '''Select AUTH_TOKEN from USERS where USERNAME = ? and PASSWORD_HASH = ? ''', (
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

        check_cursor.execute('''Select * from Users where USERNAME = ?;''', (username,))
        response = check_cursor.fetchall()

        check_cursor.close()
        db.close()

        return len(response) > 0

    def get_login_data(self, username, password):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select USER_ID, AUTH_TOKEN, LAST_LOGIN, PASSWORD_EXPIRE_DATE from USERS where USERNAME = ? and 
            PASSWORD_HASH = ? ''', (username, hash_password(password)))
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
            '''Select USERS.USER_ID, USERS.USERNAME, USERS.FIRST_NAME, USERS.LAST_NAME, USERS.EMAIL, USERS.ACCOUNT_TYPE, 
            USERS.LAST_LOGIN, USERS.PASSWORD_EXPIRE_DATE, FORGOTPASSWORD.SUBMISSIONDATE from USERS LEFT JOIN 
            FORGOTPASSWORD USING(USER_ID) UNION SELECT USERS.USER_ID, USERS.USERNAME, USERS.FIRST_NAME, 
            USERS.LAST_NAME, USERS.EMAIL, USERS.ACCOUNT_TYPE, USERS.LAST_LOGIN, USERS.PASSWORD_EXPIRE_DATE, 
            FORGOTPASSWORD.SUBMISSIONDATE FROM FORGOTPASSWORD LEFT JOIN USERS USING(USER_ID)''')

        results = list()
        results.extend(cursor.fetchall())
        if len(results) is 0:
            return None
        results_dict_list = list()
        for result in results:
            results_dict_list.append(
                {"user_id": result[0], "username": result[1], "first_name": result[2], "last_name": result[3],
                 "email": result[4], "user_type": result[5], "last_login": result[6],
                 "password_expiration_date": result[7], "forgot_password": (False if result[8] is None else True)})
        return results_dict_list

    def set_user_type(self, user_id, account_type):
        if account_type not in self.user_types:
            raise InvalidUserType(account_type, self.user_types)
        self.update_data("USERS", "ACCOUNT_TYPE", "USER_ID", user_id, account_type)
        return self.get_user_type(user_id) == account_type

    def update_password(self, user_id, new_password):
        self.update_data("USERS", "PASSWORD_HASH", "USER_ID", user_id, hash_password(new_password))
        self.remove_data("FORGOTPASSWORD", "USER_ID", user_id)
        logging.debug("New Password: " + hash_password(new_password))
        logging.debug("Set Password: " + self.get_data("USERS", "PASSWORD_HASH", "USER_ID", user_id)[0][0])
        return hash_password(new_password) == self.get_data("USERS", "PASSWORD_HASH", "USER_ID", user_id)[0][0]

    def update_last_login(self, user_id, last_login):
        self.update_data("USERS", "LAST_LOGIN", "USER_ID", user_id, self.get_date_string(last_login))
        return True  # TODO Verify update has occurred

    def set_password_expire(self, user_id, password_expire_date):
        self.update_data("USERS", "PASSWORD_EXPIRE_DATE", "USER_ID", user_id, password_expire_date)
        return True  # TODO Verify update has occurred

    def forgot_password(self, user_id):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()
        cursor.execute('''Insert into FORGOTPASSWORD (USER_ID, SUBMISSIONDATE) values (?, ?)''', (
            user_id, self.get_date_string(datetime.today())))
        db.commit()
        cursor.close()
        db.close()

        return len(self.get_data('FORGOTPASSWORD', identifier_type='USER_ID', identifier=user_id)) >= 1

    def get_forgotten_passwords(self):
        # TODO Optimize this so it can all be done with a single request
        data = self.get_data("FORGOTPASSWORD", "*")
        response_list = list()
        for user_data in data:
            response_list.append({"user_id": user_data[0], "username": self.get_username(user_data[0]),
                                  "date_forgotten": user_data[1],
                                  "last_login": self.get_last_login(user_data[0])[0][0]})
        return response_list

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

        cursor.execute("UPDATE {} SET {} = :data where {} is :identifier;".format(table, field, identifier_type),
                       {"data": data, "identifier": identifier})

        db.commit()
        cursor.close()
        db.close()

    def get_data(self, table, field="*", identifier_type=None, identifier=None):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        if identifier_type is not None:
            cursor.execute("Select {} from {} where {} is ?".format(field, table, identifier_type), (identifier,))
        else:
            cursor.execute("Select {} from {}".format(field, table))

        results = list()
        results.extend(cursor.fetchall())
        logging.debug(str(results))
        if len(results) is 0:
            return None
        return results

    def remove_data(self, table, identifier_type, identifier):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute("DELETE FROM {} where {} is ?".format(table, identifier_type), (identifier,))

        db.commit()
        cursor.close()
        db.close()

    def verify_user(self, auth_token, user_id):
        logging.debug("Verifying user " + str(user_id) if user_id is not None else "None" + " with auth_token " +
                                                                                   auth_token if auth_token is not None else "None")

        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''SELECT USERNAME FROM USERS WHERE AUTH_TOKEN is ? and USER_ID is ? ''', (auth_token, user_id))

        results = cursor.fetchall()
        logging.debug("There are " + str(len(results)) + " who match this verification information")
        return len(results) == 1

    def get_user_has_account_access(self, user_id, account_id):
        return True
        # account_type = self.get_user_type(user_id)
        # if account_type == 'admin':
        #     return True
        # if account_type == 'manager':  # Keeping these separate because these authorizations might change
        #     return True

        # db = sqlite3.connect(self.database_file_name)
        # cursor = db.cursor()
        #
        # command = '''Select * from USER_ACCOUNT_ACCESS where USER_ID is '%s' and ACCOUNT_ID is '%s' ''' % (
        #     user_id, account_id)
        # logging.debug(command)
        # cursor.execute(command)
        #
        # results = list()
        # results.extend(cursor.fetchall())
        # logging.debug(str(results))
        #
        # if results is None or len(results) is 0:
        #     return False
        # else:
        #     return True

    def set_user_account_access(self, user_id, account_id, can_access):
        if can_access:
            if self.get_user_has_account_access(user_id, account_id):
                return True  # Do nothing, already has access
            else:
                db = sqlite3.connect(self.database_file_name)
                cursor = db.cursor()

                cursor.execute('''Insert into USER_ACCOUNT_ACCESS (USER_ID, ACCOUNT_ID) values (?, ?)''', (
                    user_id, account_id))
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

                cursor.execute('''DELETE FROM USER_ACCOUNT_ACCESS where USER_ID is ? and ACCOUNT_ID is ? ''',
                               (user_id, account_id))
                db.commit()
                cursor.close()
                db.close()
                return not self.get_user_has_account_access(user_id, account_id)

    def get_accounts(self):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select ACCOUNT_ID, ACCOUNT_TITLE, NORMAL_SIDE, DATE_CREATED, CREATED_BY, LAST_EDITED_DATE, 
            LAST_EDITED_BY, DESCRIPTION, IS_ACTIVE, CATEGORY, SUBCATEGORY from ACCOUNTS''')

        results = list()
        results.extend(cursor.fetchall())

        db.commit()
        cursor.close()

        if len(results) is 0:
            return None

        results_dict_list = list()
        for result in results:
            transactions_cursor = db.cursor()

            transactions_cursor.execute('''Select DATE, DESCRIPTION, POSTING_REFERENCE, AMOUNT
                            from transactions left join JOURNAL_ENTRIES ON TRANSACTIONS.JOURNAL_ENTRY_ID = JOURNAL_ENTRIES.JOURNAL_ENTRY_ID
                            where TRANSACTIONS.ACCOUNT_ID is ? and JOURNAL_ENTRIES.STATUS is not null and JOURNAL_ENTRIES.STATUS is 'posted'
                            order by POSTING_REFERENCE;''',
                                        (result[0],))

            transactions = transactions_cursor.fetchall()
            transaction_dict_list = list()

            for transaction in transactions:
                transaction_dict_list.append({"date": transaction[0], "description": transaction[1],
                                              "posting_reference": transaction[2], "amount": transaction[3]})
            transactions_cursor.close()

            results_dict_list.append(
                {"account_id": result[0], "account_title": result[1], "normal_side": result[2],
                 "balance": self.get_account_balance(result[0]), "date_created": result[3], "created_by": result[4],
                 "last_edited_date": result[5], "last_edited_by": result[6], "description": result[7],
                 "is_active": result[8], "category": result[9], "subcategory": result[10],
                 "transactions": transaction_dict_list})

        db.close()

        return results_dict_list

    def get_viewable_accounts(self, user_id):
        return self.get_accounts()

        # db = sqlite3.connect(self.database_file_name)
        # cursor = db.cursor()
        #
        # command = '''Select ACCOUNT_ID, ACCOUNT_TITLE, NORMAL_SIDE, BALANCE, DATE_CREATED, CREATED_BY, LAST_EDITED_DATE,
        #     LAST_EDITED_BY, DESCRIPTION, IS_ACTIVE From ACCOUNTS where ACCOUNT.ACCOUNT_ID in
        #     (SELECT ACCOUNT_ID FROM USER_ACCOUNT_ACCESS where USER_ID is %s)''' % user_id
        # logging.debug(command)
        #
        # cursor.execute(command)
        # results = list()
        # results.extend(cursor.fetchall())
        # logging.debug(str(results))
        #
        # db.commit()
        # cursor.close()
        # db.close()
        #
        # results_dict_list = list()
        # for result in results:
        #     results_dict_list.append(
        #         {"account_id": result[0], "account_title": result[1], "normal_side": result[2], "balance": result[3],
        #          "date_created": result[4], "created_by": result[5], "last_edited_date": result[6],
        #          "last_edited_by": result[7], "description": result[8], "is_active": result[9]})
        # return results_dict_list

    def get_account(self, account_id):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute('''Select ACCOUNT_ID, ACCOUNT_TITLE, NORMAL_SIDE, DATE_CREATED, CREATED_BY, LAST_EDITED_DATE, 
                    LAST_EDITED_BY, DESCRIPTION, IS_ACTIVE From ACCOUNTS where ACCOUNT_ID is ?''', (account_id,))

        results = list()
        results.extend(cursor.fetchall())
        logging.debug(str(results))

        if len(results) == 0:
            return None

        if len(results) > 1:
            raise DuplicateIDException(
                message='The account with ID ' + account_id + " is associated with multiple accounts")

        result = results[0]

        cursor.close()

        transactions_cursor = db.cursor()

        transactions_cursor.execute('''Select DATE, DESCRIPTION, POSTING_REFERENCE, AMOUNT
                from transactions left join JOURNAL_ENTRIES ON TRANSACTIONS.JOURNAL_ENTRY_ID = JOURNAL_ENTRIES.JOURNAL_ENTRY_ID
                where TRANSACTIONS.ACCOUNT_ID is ? and JOURNAL_ENTRIES.STATUS is not null and JOURNAL_ENTRIES.STATUS is 'posted'
                order by POSTING_REFERENCE;''',
                                    (account_id,))

        transactions = transactions_cursor.fetchall()
        transaction_dict_list = list()

        for transaction in transactions:
            transaction_dict_list.append({"date": transaction[0], "description": transaction[1],
                                          "posting_reference": transaction[2], "amount": transaction[3]})
        transactions_cursor.close()
        db.commit()
        db.close()

        results_dict = {"account_id": result[0], "account_title": result[1], "normal_side": result[2],
                        "balance": self.get_account_balance(result[0]), "date_created": result[3],
                        "created_by": result[4], "last_edited_date": result[5], "last_edited_by": result[6],
                        "description": result[7], "is_active": result[8], "transactions": transaction_dict_list}
        return results_dict

    def get_table(self, table_name):
        return self.get_data(table_name)

    def get_user(self, user_id):
        db = sqlite3.connect(self.database_file_name)
        cursor = db.cursor()

        cursor.execute(
            '''Select USER_ID, USERNAME, FIRST_NAME, LAST_NAME, EMAIL, ACCOUNT_TYPE, LAST_LOGIN, 
            PASSWORD_EXPIRE_DATE from USERS where USER_ID is ?''', (user_id,))

        results = list()
        results.extend(cursor.fetchall())
        if len(results) is 0:
            return None

        result = {"user_id": results[0][0], "username": results[0][1], "first_name": results[0][2],
                  "last_name": results[0][3],
                  "email": results[0][4], "user_type": results[0][5], "last_login": results[0][6],
                  "password_expiration_date": results[0][7]}

        return result

    def set_user_data(self, user_id, category, value):
        self.update_data("USERS", category, "USER_ID", user_id, value)
        return value == self.get_data("USERS", category, "USER_ID", user_id)

    def create_journal_entry(self, transactions_list, user_id, date, description, journal_type):
        db = sqlite3.connect(self.database_file_name)
        create_journal_cursor = db.cursor()
        create_journal_cursor.execute('''Insert into JOURNAL_ENTRIES (USER_ID, DATE, DESCRIPTION, TYPE, STATUS) 
        values (?, ?, ?, ?, ?);''', (user_id, date, description, journal_type, 'pending'))
        db.commit()

        # get_journal_id_cursor = db.cursor()
        # journal_id_response = get_journal_id_cursor.execute('SELECT last_insert_rowid()').fetchall()[0]
        # logging.debug("Journal ID:" + journal_id_response)
        # journal_id = journal_id_response[0][0]
        # get_journal_id_cursor.close()
        journal_id = create_journal_cursor.lastrowid
        create_journal_cursor.close()
        try:
            float(journal_id)
        except ValueError:
            return None

        for transaction in transactions_list:
            create_transaction_cursor = db.cursor()
            create_transaction_cursor.execute(
                '''Insert into TRANSACTIONS(ACCOUNT_ID, AMOUNT, JOURNAL_ENTRY_ID) values (?, ?, ?)''',
                (transaction['account_id'], transaction['amount'], journal_id))
            db.commit()
            create_journal_cursor.close()

        db.close()
        return journal_id

    def get_journal_entry(self, journal_entry_id):
        db = sqlite3.connect(self.database_file_name)
        journal_cursor = db.cursor()

        journal_cursor.execute(
            '''Select JOURNAL_ENTRY_ID, USER_ID, DATE, DESCRIPTION, TYPE, STATUS, POSTING_REFERENCE, POSTING_MANAGER
            from JOURNAL_ENTRIES WHERE JOURNAL_ENTRY_ID is ? ''', (journal_entry_id,))

        results = list()
        results.extend(journal_cursor.fetchall())

        journal_cursor.close()

        if len(results) is 0:
            return None

        if len(results) > 1:
            raise DuplicateIDException(message="The journal entry ID " + journal_entry_id +
                                               " is associated with multiple journal entries")

        result = results[0]

        transaction_cursor = db.cursor()

        transaction_cursor.execute(
            '''Select TRANSACTIONS.ACCOUNT_ID, TRANSACTIONS.AMOUNT, ACCOUNTS.ACCOUNT_TITLE from TRANSACTIONS 
             left join ACCOUNTS on TRANSACTIONS.ACCOUNT_ID = ACCOUNTS.ACCOUNT_ID
             where JOURNAL_ENTRY_ID is ? ''', (result[0],))

        transactions = list()
        transactions.extend(transaction_cursor.fetchall())

        transaction_cursor.close()

        transactions_dicts = list()

        for transaction in transactions:
            transactions_dicts.append({"account_id": transaction[0], "amount": transaction[1],
                                       "account_title": transaction[2]})

        transactions_dicts.sort(reverse=True, key=get_transaction_amount)

        results_dict = {"journal_entry_id": result[0], "user_id": result[1], "date": result[2],
                        "description": result[3], "type": result[4], "status": result[5],
                        "posting_reference": result[6],
                        "posting_manager": result[7], "transactions": transactions_dicts}

        db.close()
        return results_dict

    def get_user_has_journal_access(self, user_id, journal_entry_id):
        if self.get_user_type(user_id) == "admin":
            return False
        if self.get_user_type(user_id) == "manager":
            return True
        return False  # TODO Check with the User Journal Access table to verify

    def get_viewable_journal_entries(self, user_id):
        db = sqlite3.connect(self.database_file_name)
        journal_cursor = db.cursor()

        journal_cursor.execute(
            '''Select JOURNAL_ENTRY_ID, USER_ID, DATE, DESCRIPTION, TYPE, STATUS, POSTING_REFERENCE, POSTING_MANAGER
            from JOURNAL_ENTRIES''')

        results = list()
        results.extend(journal_cursor.fetchall())

        journal_cursor.close()

        if len(results) is 0:
            return None

        results_dict_list = list()
        for result in results:
            transaction_cursor = db.cursor()

            transaction_cursor.execute(
                '''Select TRANSACTIONS.ACCOUNT_ID, TRANSACTIONS.AMOUNT, ACCOUNTS.ACCOUNT_TITLE from TRANSACTIONS 
                 left join ACCOUNTS on TRANSACTIONS.ACCOUNT_ID = ACCOUNTS.ACCOUNT_ID where JOURNAL_ENTRY_ID is ? ''',
                (result[0],))

            transactions = list()
            transactions.extend(transaction_cursor.fetchall())

            transaction_cursor.close()

            transactions_dicts = list()

            for transaction in transactions:
                transactions_dicts.append({"account_id": transaction[0], "amount": transaction[1],
                                           "account_title": transaction[2]})

            transactions_dicts.sort(reverse=True, key=get_transaction_amount)

            results_dict_list.append(
                {"journal_entry_id": result[0], "user_id": result[1], "date": result[2],
                 "description": result[3], "type": result[4], "status": result[5], "posting_reference": result[6],
                 "posting_manager": result[7], "transactions": transactions_dicts})

        db.close()
        return results_dict_list

    def set_journal_entry_data(self, journal_entry_id, category, value):
        self.update_data("JOURNAL_ENTRIES", category, "JOURNAL_ENTRY_ID", journal_entry_id, value)
        return str(value) == str(self.get_journal_entry_data(journal_entry_id, category))

    def get_journal_entry_data(self, journal_entry_id, category):
        return self.get_data("JOURNAL_ENTRIES", category, "JOURNAL_ENTRY_ID", journal_entry_id)[0][0]

    def post_journal_entry(self, journal_entry_id, user_id):
        db = sqlite3.connect(self.database_file_name)
        post_journal_cursor = db.cursor()
        post_journal_cursor.execute(
            '''Insert into POSTINGS (JOURNAL_ENTRY_ID, POSTING_MANAGER, POSTING_DATE)  values (?, ?, ?);''',
            (journal_entry_id, user_id, datetime.today().strftime(self.date_string_format)))
        db.commit()

        posting_reference = post_journal_cursor.lastrowid
        post_journal_cursor.close()
        try:
            float(posting_reference)
        except ValueError:
            return None

        #

        db.close()
        return posting_reference

    def get_account_balance(self, account_id):
        db = sqlite3.connect(self.database_file_name)
        amount_cursor = db.cursor()

        amount_cursor.execute('''Select Sum(Transactions.Amount) from transactions where Transactions.Account_ID is ? 
                                and Transactions.Journal_Entry_ID in (Select Journal_Entries.Journal_Entry_ID from 
                                Journal_Entries where Journal_Entries.Status is 'posted')''', (account_id,))
        amount = amount_cursor.fetchall()

        db.commit()
        amount_cursor.close()
        db.close()
        return amount[0][0] if amount[0][0] is not None else 0


class InvalidUserType(PostitHTTPError):
    def __init__(self, user_type, account_types):
        PostitHTTPError.__init__(self,
                                 "Invalid user type: " + user_type + ". Not in list of acceptable account types: " +
                                 str(account_types))


class DuplicateIDException(PostitHTTPError):
    def __init__(self, id_type=None, identifier=None, message=None):
        PostitHTTPError.__init__(self,
                                 "A user with the " + id_type + " " + identifier + " already exists." if
                                 message is None else message)


def generate_auth_token():
    pass
    return secrets.token_urlsafe()


def hash_password(password):
    m = hashlib.sha256()
    m.update(password.encode())
    return str(m.hexdigest())


def get_transaction_amount(transaction):
    return transaction['amount']
