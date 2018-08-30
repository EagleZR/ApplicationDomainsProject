from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController


class DummyDatabaseController(AbstractDatabaseController):
    def __init__(self):
        AbstractDatabaseController.__init__(self)

    def add_user(self, username, password, name):
        return True

    def get_user_auth_token(self, username, password):
        if username is "admin":
            return 1000
        if username is "manager":
            return 500
        if username is "user":
            return 250
        if username is "invalid":
            return None
        return 100

    def get_user_id(self, username, password):
        if username is "admin":
            return 100
        if username is "manager":
            return 50
        if username is "user":
            return 25
        if username is "invalid":
            return None
        return 1
