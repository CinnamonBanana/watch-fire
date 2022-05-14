
# my_conn = create_engine("sqlite:///my_db.db")
# r_set=my_conn.execute('''SELECT * from student WHERE "mark">=75''')


from mimetypes import init
import sqlite3

class Database:
    def __init__(self) -> None:
        self.config()

    def config(self):
        try:
            sqlite_connection = sqlite3.connect('wfdb.db')
            cursor = sqlite_connection.cursor()
            with open('./modules/tables.sql', 'r') as sqlite_file:
                sql_script = sqlite_file.read()
            cursor.executescript(sql_script)
            cursor.close()

        except sqlite3.Error as error:
            print("Ошибка при подключении к sqlite", error)
        finally:
            if (sqlite_connection):
                sqlite_connection.close()
    
    def get_hosts(self, blocked=False):
        try:
            sqlite_connection = sqlite3.connect('wfdb.db')
            cursor = sqlite_connection.cursor()
            sql = '''SELECT status, name, ip FROM hosts '''
            if blocked:
                sql += '''WHERE "status" = "R"'''
            res = list(cursor.execute(sql))
            cursor.close()
            sqlite_connection.close()
            return res

        except sqlite3.Error as error:
            print("Ошибка при подключении к sqlite", error)
        finally:
            if (sqlite_connection):
                sqlite_connection.close()

    def add_host(self, data):
        pass

if __name__ == "__main__":
    db = Database()
    db.get_hosts()