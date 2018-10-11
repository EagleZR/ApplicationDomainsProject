import logging
import os.path
import pickle
from datetime import datetime

file_name = os.path.dirname(os.path.abspath(__file__)) + "\\EventLog"
date_string_format = "%d-%b-%Y %H:%M:%S"


def format_log_entry(log_entry):
    return "[User ID: " + log_entry['user_id'] + "]: " + log_entry['timestamp'] + " -- " + log_entry['message']


class EventLog:
    def __init__(self):
        self.is_open = True  # TODO Why do I have this? 

        if os.path.isfile(file_name):
            logging.info("EventLog already exists")
            file = open(file_name, "rb")
            data = file.read()
            self.log = pickle.loads(data)
            file.close()
        else:
            logging.warning("!!!!!!!!EVENTLOG FILE DOES NOT EXIST!!!!!!!!")
            logging.warning("Creating new EventLog")
            self.log = list()
            self.write(1, "Created Log")  # Attribute any automatic actions to the root admin

    def write(self, user_id, text):
        if self.is_open:
            logging.info("Writing to EventLog: \t" + text)
            self.log.append({"user_id": user_id, "message": text,
                             "timestamp": datetime.today().strftime(date_string_format)})
            self.save()

    def read_last(self):
        if self.is_open:
            return format_log_entry(self.log[len(self.log) - 1])
        return None

    def read_all_as_text(self):
        if self.is_open:
            return_string = ""
            for s in self.log:
                return_string += format_log_entry(s)
            return return_string
        return None

    def get_all(self):
        if self.is_open:
            return self.log
        return None

    def read_from_user_as_text(self, user_id):
        if self.is_open:
            return_string = ""
            for s in self.log:
                if str(s['user_id']) == str(user_id):
                    return_string += format_log_entry(s)
            return return_string
        return None

    def get_from_user(self, user_id):
        if self.is_open:
            return_list = list()
            for s in self.log:
                if str(s['user_id'] == user_id):
                    return_list += s
            return return_list
        return None

    def close(self):
        if self.is_open:
            self.save()
            self.is_open = False

    def save(self):
        if self.is_open:
            data = pickle.dumps(self.log)
            file = open(file_name, "wb+")
            file.write(data)
            file.close()
