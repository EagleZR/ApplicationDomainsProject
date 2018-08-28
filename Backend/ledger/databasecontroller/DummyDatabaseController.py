from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController


class DummyDatabaseController(AbstractDatabaseController):
    def __init__(self):
        AbstractDatabaseController.__init__(self)

    def get_user_auth_token(self, username, password_hash):
        if username is "admin":
            return 1000
        if username is "manager":
            return 500
        if username is "user":
            return 250
        return 100

    def get_user_id(self, username, password_hash):
        if username is "admin":
            return 100
        if username is "manager":
            return 50
        if username is "user":
            return 25
        return 1
