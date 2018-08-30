import abc


class AbstractDatabaseController(abc.ABC):
    def __init__(self):
        self.account_types = ["admin", "manager", "user", "deactivated"]
        pass

    @abc.abstractmethod
    def add_user(self, username, password_hash, account_type="deactivated"):
        pass

    @abc.abstractmethod
    def get_user_id(self, username, password_hash):
        pass

    @abc.abstractmethod
    def get_user_auth_token(self, username, password_hash):
        pass
