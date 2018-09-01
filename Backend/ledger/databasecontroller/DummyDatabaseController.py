from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController


class DummyDatabaseController(AbstractDatabaseController):

    def __init__(self):
        AbstractDatabaseController.__init__(self)

    def add_user(self, email, password, name):
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

    def get_user_id(self, email, password):
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
