import logging
import os.path
import pickle
from datetime import datetime

file_name = os.path.dirname(os.path.abspath(__file__)) + "\\EventLog"
date_string_format = "%d-%b-%Y %H:%M:%S"


class EventLog:
    def __init__(self):
        self.is_open = True
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
            self.write("Created Log")

    def write(self, text):
        if self.is_open:
            self.log.append(datetime.today().strftime(date_string_format) + "-- " + text)
            self.save()

    def read_last(self):
        if self.is_open:
            return self.log[len(self.log) - 1]
        return None

    def read_all(self):
        if self.is_open:
            return_string = ""
            for s in self.log:
                return_string += s + "\n"
            return return_string
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
