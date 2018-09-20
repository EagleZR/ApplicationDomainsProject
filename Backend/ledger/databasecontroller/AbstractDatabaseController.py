import abc
from datetime import datetime, timedelta


class AbstractDatabaseController(abc.ABC):
    def __init__(self):
        self.account_types = ["admin", "manager", "user", "deactivated", "new"]
        # New users have to change their password
        self.default_account_type = "new"
        self.date_string_format = "%d-%b-%Y"
        self.password_duration = 30

    @abc.abstractmethod
    def add_user(self, email, password, name, password_expire_date):
        pass

    @abc.abstractmethod
    def get_user_id(self, email=None, password=None, auth_token=None):
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

    @abc.abstractmethod
    def update_password(self, user_id, new_password):
        pass

    @abc.abstractmethod
    def update_last_login(self, user_id, last_login):
        pass

    @abc.abstractmethod
    def set_password_expire(self, user_id, password_expire_date):
        pass

    def get_30_days_from_now(self):
        return (datetime.today() + timedelta(days=self.password_duration)).strftime(self.date_string_format)
