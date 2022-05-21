
# my_conn = create_engine("sqlite:///my_db.db")
# r_set=my_conn.execute('''SELECT * from student WHERE "mark">=75''')

import sqlite3, datetime

class Database:
    
    dbf = 'wfdb.db'

    def __init__(self):
        self.config()

    def config(self):
        try:
            sqlite_connection = sqlite3.connect(self.dbf)
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
    
    def query(self, query, data=None, oneCol=False):
        try:
            sqlite_connection = sqlite3.connect(self.dbf)
            cursor = sqlite_connection.cursor()
            if oneCol:
                cursor.row_factory = lambda cursor, row: row[0]
            if data:
                data = tuple(data.values())
                data += (datetime.datetime.now().timestamp(),)
                cursor.execute(query, data)
                sqlite_connection.commit()
                res=True
            else:
                res = list(cursor.execute(query))            
            cursor.close()
        except sqlite3.Error as error:
            print("Ошибка при подключении к sqlite", error)
            res = False
        finally:
            if (sqlite_connection):
                sqlite_connection.close()
            return res

    def get_hosts(self, blocked=False):
        sql = '''SELECT status, name, ip, last_edit FROM hosts '''
        if blocked:
                sql += '''WHERE "status" = "R"'''
        return self.query(query=sql)

    def get_host(self, ip):
        sql = f'''SELECT * FROM hosts WHERE "ip" = "{ip}"'''
        res = self.query(query=sql)
        return res[0] if res else None

    def get_ips(self, blocked=False):
        sql = '''SELECT ip FROM hosts '''
        if blocked:
                sql += '''WHERE "status" = "R"'''
        return self.query(query=sql, oneCol=True)

    def add_host(self, data):
        sql = f'''INSERT INTO 'hosts' ('name','ip','status','badscore','token','last_edit') 
                                VALUES (?, ?, ?, ?, ?, ?);'''
        self.query(query=sql, data=data)

    def edit_host(self, ip, data):
        sql = f'''UPDATE 'hosts' SET '''
        for key in data.keys():
            sql += f'''{key} = ?, '''
        sql += f'''last_edit = ? WHERE ip = '{ip}';'''
        self.query(query=sql, data=data)

if __name__ == "__main__":
    db = Database()
    #data = {'name':"NewPC", 'ip':'1.1.1.1', 'status':"G", 'badscore':'0', 'token':"testtoken"}
    #db.add_host(data)
    print(db.get_host('192.168.1.64'))
    print(db.get_hosts())