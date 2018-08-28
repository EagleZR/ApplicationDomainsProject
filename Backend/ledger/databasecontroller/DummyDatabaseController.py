from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController


class DummyDatabaseController(AbstractDatabaseController):
    def __init__(self):
        AbstractDatabaseController.__init__(self)

    def get_user_auth_token(self, username, password_hash):
        return 100

    def get_user_id(self, username, password_hash):
        return 1
