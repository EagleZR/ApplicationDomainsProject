try:
    import unittest2 as unittest
except ImportError:
    import unittest
import os

from ledger.databasecontroller.SQLITEDatabaseController import SQLITEDatabaseController
from ledger.databasecontroller.SQLITEDatabaseController import DuplicateEmailException


class SQLITEDatabaseControllerTest(unittest.TestCase):
    """This test creates and destroys databases. DO NOT use this in a production environment.

    """

    def setUp(self):
        database_file_path = os.getcwd() + '\\..\\..\\..\\ledger\\databasecontroller\\sqlitedb.db'
        if os.path.isfile(database_file_path):
            os.remove(database_file_path)
        SQLITEDatabaseController()
        self.assertTrue(os.path.isfile(database_file_path))

    def test_get_user_id(self):
        db = SQLITEDatabaseController()
        email = "user1"
        password = "dfiuohsdfiu"
        name = "Roger"
        self.assertTrue(db.add_user(email, password, name))
        db.get_user_id(email, password)
        # Only fails if an exception was thrown

    def test_get_auth_token(self):
        db = SQLITEDatabaseController()
        email = "user2"
        password = "efbkwbkwe"
        name = "Emily"
        self.assertTrue(db.add_user(email, password, name))
        db.get_user_auth_token(email, password)
        # Only fails if an exception was thrown

    def test_duplicate_email_exception(self):
        db = SQLITEDatabaseController()
        email = "user3"
        password = "fdkijhsdsf"
        name = "Antonio"
        self.assertTrue(db.add_user(email, password, name))
        with self.assertRaises(DuplicateEmailException) as context:
            self.assertFalse(db.add_user(email, password, name))

    def test_multiple_users(self):
        db = SQLITEDatabaseController()
        email = "user1"
        password = "dfiuohsdfiu"
        name = "Roger"
        self.assertTrue(db.add_user(email, password, name))

        db = SQLITEDatabaseController()
        email = "user2"
        password = "efbkwbkwe"
        name = "Emily"
        self.assertTrue(db.add_user(email, password, name))

        db = SQLITEDatabaseController()
        email = "user3"
        password = "fdkijhsdsf"
        name = "Antonio"
        self.assertTrue(db.add_user(email, password, name))

        self.assertTrue(db.user_exists("user1"))
        self.assertTrue(db.user_exists("user2"))
        self.assertTrue(db.user_exists("user3"))

    def test_get_login_data(self):
        db = SQLITEDatabaseController()
        email = "user1"
        password = "dfiuohsdfiu"
        name = "Roger"
        self.assertTrue(db.add_user(email, password, name))
        user_id, auth_token = db.get_login_data(email, password)
        self.assertTrue(user_id is not None)
        self.assertTrue(auth_token is not None)
