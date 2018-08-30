import unittest
import os

from ledger.databasecontroller.SQLITEDatabaseController import SQLITEDatabaseController


class SQLITEDatabaseControllerTest(unittest.TestCase):
    """This test creates and destroys databases. DO NOT use this in a production environment.

    """

    def test_database_file_location(self):
        database_file_path = os.getcwd() + '\\..\\..\\..\\ledger\\databasecontroller\\sqlitedb.db'
        if os.path.isfile(database_file_path):
            os.remove(database_file_path)
        SQLITEDatabaseController()
        self.assertTrue(os.path.isfile(database_file_path))

    def test_get_user_id(self):
        db = SQLITEDatabaseController()
        username = "user"
        password_hash = "dfiuohsdfiu"
        db.add_user(username, password_hash)
        db.get_user_id(username, password_hash)
        # Only fails if an exception was thrown

    def test_get_auth_token(self):
        db = SQLITEDatabaseController()
        username = "user"
        password_hash = "dfiuohsdfiu"
        db.add_user(username, password_hash)
        db.get_user_auth_token(username, password_hash)
        # Only fails if an exception was thrown
