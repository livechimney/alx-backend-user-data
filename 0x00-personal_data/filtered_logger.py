#!/usr/bin/env python3
""" Returns filtered logs"""

import re
import logging
import mysql.connector
from os import environ
from typing import List


patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}

PII_FIELDS = {"name", "email", "phone", "ssn", "password"}


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """ Returns a log message obfuscated by PII values"""
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)


def get_logger() -> logging.Logger:
    """ Returns a logger object"""
    logger = logging.getLogger("user_data")
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Returns a connector object to a MySQL database """
    username = environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    password = environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    host = environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = environ.get("PERSONAL_DATA_DB_NAME", "")
    cnnect = mysql.connector.connect(
        user=username,
        port=3306,
        password=password,
        host=host,
        database=db_name
        )
    return cnnect


def main():
    """ Obtain a database connection using get_db and retrieves all rows
    in the users table and display each row under a filtered format
    """
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    field_names = [i[0] for i in cursor.description]

    logger = get_logger()

    for row in cursor:
        str_row = ''.join(f'{f}={str(r)}; ' for r, f in zip(row, field_names))
        logger.info(str_row.strip())

    cursor.close()
    db.close()


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filters values in incoming log records using filter_datum"""
        msg = super(RedactingFormatter, self).format(record)
        rec = filter_datum(self.fields, self.REDACTION,
                           msg, self.SEPARATOR)
        return rec


if __name__ == "__main__":
    main()
