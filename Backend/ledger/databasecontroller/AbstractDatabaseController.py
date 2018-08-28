import abc


class AbstractDatabaseController(abc.ABC):
    def __init__(self):
        pass

    @abc.abstractmethod
    def get_user_id(self, username, password_hash):
        pass

    @abc.abstractmethod
    def get_user_auth_token(self, username, password_hash):
        pass
