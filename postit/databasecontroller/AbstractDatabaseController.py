import abc
from datetime import datetime, timedelta


class AbstractDatabaseController(abc.ABC):
    def __init__(self):
        self.account_types = ["admin", "manager", "user", "deactivated", "new"]
        # New users have to change their password
        self.default_account_type = "new"
        self.date_string_format = "%d-%b-%Y"
        self.date_time_string_format = self.date_string_format + " %H:%M:%S"
        self.password_duration = 30

    @abc.abstractmethod
    def add_user(self, username, password, email, first_name, last_name, password_expire_date):
        pass

    @abc.abstractmethod
    def get_user_id(self, username=None, auth_token=None):
        pass

    @abc.abstractmethod
    def get_user_auth_token(self, username, password):
        pass

    @abc.abstractmethod
    def get_login_data(self, username, password):
        pass

    @abc.abstractmethod
    def get_user_type(self, user_id):
        pass

    @abc.abstractmethod
    def get_all_user_accounts(self):
        pass

    @abc.abstractmethod
    def set_user_type(self, user_id, account_type):
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

    @abc.abstractmethod
    def forgot_password(self, user_id):
        pass

    @abc.abstractmethod
    def get_forgotten_passwords(self):
        pass

    @abc.abstractmethod
    def get_username(self, user_id):
        pass

    @abc.abstractmethod
    def get_last_login(self, user_id):
        pass

    @abc.abstractmethod
    def add_account(self, account_id, account_title, normal_side, description, created_by):
        pass

    @abc.abstractmethod
    def get_user_has_account_access(self, user_id, account_id):
        pass

    @abc.abstractmethod
    def set_user_account_access(self, user_id, account_id, can_access):
        pass

    @abc.abstractmethod
    def get_accounts(self):
        pass

    @abc.abstractmethod
    def get_viewable_accounts(self, user_id):
        pass

    @abc.abstractmethod
    def get_account(self, account_id):
        pass

    @abc.abstractmethod
    def get_table(self, table_name):
        pass

    @abc.abstractmethod
    def get_user(self, user_id):
        pass

    @abc.abstractmethod
    def set_user_data(self, user_id, category, value):
        pass

    @abc.abstractmethod
    def create_journal_entry(self, transactions_list, user_id, date, description):
        pass

    @abc.abstractmethod
    def get_journal_entry(self, journal_entry_id):
        pass

    @abc.abstractmethod
    def get_user_has_journal_access(self, user_id, journal_entry_id):
        pass

    @abc.abstractmethod
    def get_viewable_journal_entries(self, user_id):
        pass

    def get_30_days_from_now(self):
        return (datetime.today() + timedelta(days=self.password_duration)).strftime(self.date_string_format)

    def get_date(self, date_string):
        return datetime.strptime(date_string, self.date_string_format)

    def get_date_string(self, date):
        return datetime.strftime(date, self.date_string_format)

    def get_date_time(self, date_time_string):
        return datetime.strptime(date_time_string, self.date_time_string_format)

    def get_date_time_string(self, date):
        return datetime.strftime(date, self.date_time_string_format)
