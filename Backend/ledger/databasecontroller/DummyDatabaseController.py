from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController


class DummyDatabaseController(AbstractDatabaseController):

    def __init__(self):
        AbstractDatabaseController.__init__(self)

    def add_user(self, email, password, name):
        if email == "invalid" and password == "invalid":
            return False
        return True

    def get_user_auth_token(self, email, password):
        if email is "admin":
            return 1000
        if email is "manager":
            return 500
        if email is "user":
            return 250
        if email is "invalid":
            return None
        return 100

    def get_user_id(self, email=None, password=None, auth_token=None):
        if email is "admin":
            return 100
        if email is "manager":
            return 50
        if email is "user":
            return 25
        if email is "invalid":
            return None
        return 1

    def get_login_data(self, email, password):
        if email is "admin":
            return 100, 1000
        if email is "manager":
            return 50, 500
        if email is "user":
            return 25, 250
        if email is "invalid":
            return None
        return 1, 10

    def get_account_type(self, user_id):
        return "user"

    def get_all_user_accounts(self):
        return [{"user_id": 1, "name": "admin", "email": "admin@email.com", "account_type": "admin"},
                {"user_id": 2, "name": "manager", "email": "manager@email.com", "account_type": "manager"},
                {"user_id": 3, "name": "user", "email": "user@email.com", "account_type": "user"},
                {"user_id": 4, "name": "deactivated", "email": "deactivated@email.com", "account_type": "deactivated"},
                {"user_id": 5, "name": "new", "email": "new@email.com", "account_type": "new"}]

    def set_account_type(self, user_id, account_type):
        return True

    def verify_user(self, auth_token, user_id):
        return True
