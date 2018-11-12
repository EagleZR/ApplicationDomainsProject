import logging
import os.path
import pickle
from datetime import datetime

file_name = os.path.dirname(os.path.abspath(__file__)) + "/EventLog"
date_string_format = "%d-%b-%Y %H:%M:%S"


def format_log_entry(log_entry):
    return "[User ID: " + str(log_entry['user_id']) + "]: " + log_entry['timestamp'] + " -- " + \
           log_entry['message']


class EventLog:
    def __init__(self):
        self.log = list()
        self.update()

    def write(self, user_id, text, precondition, postcondition):
        logging.info("Writing to EventLog: \t" + text)
        self.log.append(
            {"user_id": user_id, "message": text, "precondition": precondition, "postcondition": postcondition,
             "timestamp": datetime.today().strftime(date_string_format)})
        self.save()

    def read_last(self):
        self.update()
        return format_log_entry(self.log[len(self.log) - 1])

    def read_all_as_text(self):
        self.update()
        return_string = ""
        for s in self.log:
            return_string += format_log_entry(s) + "\n"
        return return_string

    def get_all(self):
        self.update()
        return self.log

    def read_from_user_as_text(self, user_id):
        self.update()
        return_string = ""
        for message in self.log:
            if str(message['user_id']) == str(user_id):
                return_string += format_log_entry(message)
        return return_string

    def get_from_user(self, user_id):
        self.update()
        return_list = list()
        for message in self.log:
            if str(message['user_id']) == str(user_id):
                return_list.append(message)
        return return_list

    def dump(self):
        self.update()
        return_string = ""
        for s in self.log:
            logging.debug(format_log_entry(s))
        return return_string

    def save(self):
        data = pickle.dumps(self.log)
        file = open(file_name, "wb+")
        file.write(data)
        file.close()

    def update(self):
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
            self.write(1, "Created Log", "", "")  # Attribute any automatic actions to the root admin
