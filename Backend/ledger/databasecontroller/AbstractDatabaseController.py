import abc


class AbstractDatabaseController(abc.ABC):
    def __init__(self):
        self.account_types = ["admin", "manager", "user", "deactivated", "new"]
        # New users have to change their password
        self.default_account_type = "new"

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

    @abc.abstractmethod
    def get_account_type(self, user_id):
        pass

    @abc.abstractmethod
    def get_all_user_accounts(self):
        pass

    @abc.abstractmethod
    def set_account_type(self, user_id, account_type):
        pass

    @abc.abstractmethod
    def verify_user(self, auth_token, user_id):
        pass
