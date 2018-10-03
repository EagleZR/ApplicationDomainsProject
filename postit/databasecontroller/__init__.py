from postit.databasecontroller import SQLITEDatabaseController, DummyDatabaseController, AbstractDatabaseController
import logging


def get_database(database_type):
    """Returns an instance of a database controller from the given input.

    :param database_type: The type of database to be used. The options are 'dummy' and 'sqlite'.
    :type database_type: str
    :return: The controller for the specified form of database.
    :rtype: AbstractDatabaseController.AbstractDatabaseController
    """
    if database_type == 'dummy':
        logging.info("Creating a dummy db controller")
        return DummyDatabaseController.DummyDatabaseController()
    elif database_type == 'sqlite':
        logging.info("Creating a sqlite db controller")
        return SQLITEDatabaseController.SQLITEDatabaseController()
    else:
        logging.info("No db created")
