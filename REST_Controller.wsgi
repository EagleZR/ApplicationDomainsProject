#!/usr/bin/python
import sys
import logging

sys.path.insert(0, "/var/www/Postit-backend/")
logging.basicConfig(filename="/var/www/markzeagler.com/postit.log", datefmt="%d-%b-%Y %H:%M:%S", level=logging.DEBUG)

from postit import app as application
