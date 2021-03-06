import configparser
import os.path
import logging
import random
from datetime import (datetime, timedelta)
import re
import json

from postit import databasecontroller, EventLog

logging.basicConfig(filename="/var/www/markzeagler.com/postit.log", datefmt="%d-%b-%Y %H:%M:%S", level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/postit/config.ini')

upload_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), config['files']['upload_folder'])


# https://stackoverflow.com/questions/553303/generate-a-random-date-between-two-other-dates
def random_date(start, end, prop):
    return start + prop * (end - start)


config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + '/postit/config.ini')
db = databasecontroller.get_database(config['database']['database_type'])
event_log = EventLog()

##########################################
# Generate some seed data for the database
##########################################

# User seed data
email_regex = re.compile("(\S*)@")
with open(os.path.dirname(os.path.realpath(__file__)) + '/setup/user_setup_data.txt', 'r') as f:
    for line in f.readlines():
        username, password, email, first_name, last_name = line.split(', ')
        user_type = email_regex.search(email).group(1)
        db.add_user(username.strip(), password.strip(), email.strip(), first_name.strip(), last_name.strip(),
                    random_date((datetime.today() + timedelta(days=20)) + timedelta(days=10), datetime.today(),
                                random.random()).strftime(db.date_string_format))
        user_id = db.get_user_id(username)
        event_log.write(1, "Added user " + str(user_id), "", "Username: " + username)
        db.set_user_type(user_id, user_type)
        event_log.write(1, "Set user " + str(user_id) + " to " + user_type, "User Type: new",
                        "User Type: " + db.get_user_type(user_id))
        db.update_last_login(user_id, random_date((datetime.today() - timedelta(days=30)), datetime.today(),
                                                  random.random()))

# Account seed data
with open(os.path.dirname(os.path.realpath(__file__)) + '/setup/account_data_setup.txt', 'r') as f:
    for line in f.readlines():
        account_id, account_title, normal_side, description, category, subcategory = line.split(', ')
        print(str(account_id) + ", " + str(account_title) + ", " + str(normal_side) + ", " + str(
            description) + ", " + str(category) + ", " + str(subcategory))
        users = db.get_all_user_accounts()
        created_by = users[random.randrange(0, len(users))]['user_id']
        db.add_account(account_id.strip(), account_title.strip(), normal_side.strip().lower(), description.strip(),
                       category, subcategory, created_by)
        event_log.write(1, "Created account " + str(account_id), "", "Account Title: " + account_title)

# Transactions
with open(os.path.dirname(os.path.realpath(__file__)) + '/setup/journal_setup_data.json', 'r') as json_file:
    json_data = json.load(json_file)
    journal_entries = json_data['journal_entries']
    os.mkdir(os.path.join(upload_folder))
    for journal_entry in journal_entries:
        transactions = journal_entry['transactions']
        user_id = journal_entry['user_id']
        description = journal_entry['description']
        journal_type = journal_entry['journal_type']
        status = journal_entry['status']
        journal_entry_id = db.create_journal_entry(transactions, user_id,
                                                   datetime.today().strftime(db.date_string_format), description,
                                                   journal_type)
        if os.path.isdir(upload_folder + str(journal_entry_id)):
            logging.warning('The folder for a journal entry\'s files already exists. Its contents will be deleted.')
            for a_file in os.listdir(upload_folder + str(journal_entry_id)):
                path = os.path.join(upload_folder + str(journal_entry_id), a_file)
                try:
                    os.unlink(path)
                except Exception:
                    logging.warning('There was an error deleting the folder\'s contents.')
        else:
            os.mkdir(os.path.join(upload_folder, str(journal_entry_id)))

        if not status == 'pending':
            db.set_journal_entry_data(journal_entry_id, 'status', status)
            db.set_journal_entry_data(journal_entry_id, "POSTING_MANAGER", 1)
            db.set_journal_entry_data(journal_entry_id, "POSTING_REFERENCE", journal_entry_id)
            if status == 'rejected':
                db.set_journal_entry_data(journal_entry_id, 'description',
                                          db.get_journal_entry_data(journal_entry_id, 'description') + journal_entry[
                                              'rejection_reason'])

# Print logs to manually verify they work correctly
messages = event_log.get_all()

for message in messages:
    print(message)
