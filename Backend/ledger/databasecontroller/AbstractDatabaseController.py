import abc


class AbstractDatabaseController(abc.ABC):
    def __init__(self):
        self.account_types = ["admin", "manager", "user", "deactivated", "pending"]
        self.default_account_type = "user"

    @abc.abstractmethod
    def add_user(self, email, password, name):
        pass

    @abc.abstractmethod
    def get_user_id(self, email, password):
        pass

    @abc.abstractmethod
    def get_user_auth_token(self, email, password):
        pass

    @abc.abstractmethod
    def get_login_data(self, email, password):
        pass
