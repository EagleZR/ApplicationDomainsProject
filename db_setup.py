import configparser
import os.path
import re

from postit import databasecontroller

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/postit/config.ini')
db = databasecontroller.get_database(config['database']['database_type'])

# Generate some seed data for the database
email_regex = re.compile("\s(\S*)@")
with open(os.path.dirname(os.path.realpath(__file__)) + '/user_setup_data.txt', 'r') as f:
    for line in f.readlines():
        username, password, email, first_name, last_name = line.split(', ')
        user_type = email_regex.search(email).group(1)
        db.add_user(username, password, email, first_name, last_name, db.get_30_days_from_now())
        db.set_user_type(db.get_user_id(username), user_type)
