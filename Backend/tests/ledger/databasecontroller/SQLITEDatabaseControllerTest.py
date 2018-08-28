import unittest
import os.path

from ledger.databasecontroller.SQLITEDatabaseController import SQLITEDatabaseController


class SQLITEDatabaseControllerTest(unittest.TestCase):
    def test_database_file_location(self):
        SQLITEDatabaseController()
        self.assertTrue(os.path.isfile(os.getcwd() + '\\..\\..\\..\\ledger\\databasecontroller\\sqlitedb.db'))
