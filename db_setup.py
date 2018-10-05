import configparser
import os.path
import logging
import random
from datetime import (datetime, timedelta)
import re

from postit import databasecontroller

logging.basicConfig(filename="/var/www/markzeagler.com/postit.log", datefmt="%d-%b-%Y %H:%M:%S", level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')


# https://stackoverflow.com/questions/553303/generate-a-random-date-between-two-other-dates
def random_date(start, end, prop):
    return start + prop * (end - start)


config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/postit/config.ini')
db = databasecontroller.get_database(config['database']['database_type'])

# Generate some seed data for the database
email_regex = re.compile("(\S*)@")
with open(os.path.dirname(os.path.realpath(__file__)) + '/user_setup_data.txt', 'r') as f:
    for line in f.readlines():
        username, password, email, first_name, last_name = line.split(', ')
        user_type = email_regex.search(email).group(1)
        db.add_user(username, password, email, first_name, last_name, random_date((datetime.today() +
                                                                                   timedelta(days=30)),
                                                                                  datetime.today(),
                                                                                  random.random()))
        user_id = db.get_user_id(username)
        db.set_user_type(user_id, user_type)
        db.update_last_login(user_id, random_date((datetime.today() - timedelta(days=30)), datetime.today(),
                                                  random.random()))
