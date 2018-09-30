from ledger.databasecontroller.AbstractDatabaseController import AbstractDatabaseController


class DummyDatabaseController(AbstractDatabaseController):

    def get_table(self, table_name):
        pass

    def get_account(self, account_id):
        pass

    def get_user_has_account_access(self, user_id, account_id):
        pass

    def set_user_account_access(self, user_id, account_id, can_access):
        pass

    def get_accounts(self):
        pass

    def get_viewable_accounts(self, user_id):
        pass

    def get_last_login(self, user_id):
        pass

    def get_username(self, user_id):
        return "username"

    def forgot_password(self, user_id):
        pass

    def get_forgotten_passwords(self):
        pass

    def __init__(self):
        AbstractDatabaseController.__init__(self)

    def add_user(self, email, password, name, password_expire_date):
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

    def get_user_id(self, email=None, auth_token=None):
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
            return 100, 1000, "12-Dec-2012", 12
        if email is "manager":
            return 50, 500, "12-Dec-2012", 0
        if email is "user":
            return 25, 250, "12-Dec-2012", 25
        if email is "invalid":
            return None
        return 1, 10, "12-Dec-2012", 18

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

    def update_password(self, user_id, new_password):
        return True

    def update_last_login(self, user_id, last_login):
        return True

    def set_password_expire(self, user_id, password_expire_date):
        pass
