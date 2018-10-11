try:
    import unittest2 as unittest
except ImportError:
    import unittest
import os

from postit.databasecontroller.SQLITEDatabaseController import SQLITEDatabaseController
from postit.databasecontroller.SQLITEDatabaseController import DuplicateIDException


class SQLITEDatabaseControllerTest(unittest.TestCase):
    """This test creates and destroys databases. DO NOT use this in a production environment.

    """

    def setUp(self):
        database_file_path = os.getcwd() + '\\..\\..\\..\\postit\\databasecontroller\\sqlitedb.db'
        if os.path.isfile(database_file_path):
            os.remove(database_file_path)
        SQLITEDatabaseController()
        self.assertTrue(os.path.isfile(database_file_path))
        self.db = SQLITEDatabaseController()
        self.username = "user1"
        self.password = "dfiuohsdfiu"
        self.first_name = "Roger"
        self.last_name = "Doe"
        self.email = "fesfsd@sdfsd.com"
        self.assertTrue(self.db.add_user(self.username, self.password, self.email, self.first_name, self.last_name,
                                         self.db.get_30_days_from_now()))

    def test_get_user_id(self):
        self.assertNotEqual(None, self.db.get_user_id(self.username))

    def test_get_auth_token(self):
        self.assertNotEqual(None, self.db.get_user_auth_token(self.username, self.password))

    def test_duplicate_email_exception(self):
        with self.assertRaises(DuplicateIDException) as context:
            self.assertFalse(self.db.add_user(self.username, self.password, self.email, self.first_name, self.last_name,
                                              self.db.get_30_days_from_now()))

    def test_multiple_users(self):
        username = "user2"
        password = "fgdsfgfsb"
        first_name = "Daniel"
        last_name = "Reed"
        email = "fesfsdfdsfssd@fdgfgfd.com"
        self.assertTrue(
            self.db.add_user(username, password, email, first_name, last_name, self.db.get_30_days_from_now()))

        username = "user3"
        password = "gdfgfdgfd"
        first_name = "Andy"
        last_name = "Richard"
        email = "dfsddfsdfh@kjljklk.com"
        self.assertTrue(
            self.db.add_user(username, password, email, first_name, last_name, self.db.get_30_days_from_now()))

        self.assertTrue(self.db.user_exists("user1"))
        self.assertTrue(self.db.user_exists("user2"))
        self.assertTrue(self.db.user_exists("user3"))

    def test_get_login_data(self):
        user_id, auth_token, last_login, password_expire_date = self.db.get_login_data(self.username, self.password)
        self.assertTrue(user_id is not None)
        self.assertTrue(auth_token is not None)
        self.assertTrue(password_expire_date is not None)

    def test_invalid_user_login(self):
        user_id, auth_token, var3, var4 = self.db.get_login_data("fgdfgdf", "fsfdsfs")
        self.assertTrue(user_id is None)
        self.assertTrue(auth_token is None)

    def test_get_all_users(self):
        usernames = list()
        usernames.append(self.username)

        username = "user2"
        password = "efbkwbkwe"
        first_name = "Emily"
        last_name = "Smith"
        email = "dsfdsfsd@sdfdsfds.com"
        self.assertTrue(
            self.db.add_user(username, password, email, first_name, last_name, self.db.get_30_days_from_now()))
        usernames.append(username)

        username = "user3"
        password = "dfsglsdfgkjdfglkj"
        first_name = "Jessica"
        last_name = "Allen"
        email = "hjkmfhjm@jgkughdy.com"
        self.assertTrue(
            self.db.add_user(username, password, email, first_name, last_name, self.db.get_30_days_from_now()))
        usernames.append(username)

        users = self.db.get_all_user_accounts()
        # Admin is automatically created, so there will be 1 more user in the db
        self.assertEqual(len(usernames) + 1, len(users))

        for username in usernames:
            self.assertTrue(user_list_contains("username", username, users))


def user_list_contains(category, value, users):
    for user in users:
        if user[category] == value:
            return True
    return False
