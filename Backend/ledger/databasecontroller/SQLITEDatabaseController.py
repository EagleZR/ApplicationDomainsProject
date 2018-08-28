from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController
import logging
import os.path
import sqlite3

database_file_name = os.path.dirname(os.path.realpath(__file__)) + '\\sqlitedb.db'


class SQLITEDatabaseController(AbstractDatabaseController):
    def __init__(self):
        AbstractDatabaseController.__init__(self)
        if not os.path.isfile(database_file_name):
            logging.warning("The database did not exist, a new one is being created.")
        self.db = sqlite3.connect(database_file_name)
        self.verify_tables_columns()

    def verify_tables_columns(self):
        # TODO Make sure each table exists and possess the correct columns. If possible, add the tables.
        pass

    def get_user_id(self, username, password_hash):
        pass

    def get_user_auth_token(self, username, password_hash):
        pass
