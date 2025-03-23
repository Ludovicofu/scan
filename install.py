import configparser
import os
import pymysql

from django.conf import settings
settings.configure()

# 读取 config.ini 获取数据库配置信息
conf = configparser.ConfigParser()
conf.read(os.path.join(os.getcwd(), "config.ini"))

mysql_config = {
    'host': conf.get('database', 'host'),
    'port': int(conf.get('database', 'port')),
    'user': conf.get('database', 'user'),
    'password': conf.get('database', 'password'),
    'database': conf.get('database', 'name'),
    "connect_timeout": 1
}

# 读取 SQL 文件并执行
def exec_sql_file(conn, file_path):
    with open(file_path, "r", encoding="utf-8") as sql_file:
        sql_commands = sql_file.read().split(";")  # 按 `;` 分割 SQL 语句
        cursor = conn.cursor()
        for sql in sql_commands:
            if sql.strip():  # 确保 SQL 语句不为空
                try:
                    cursor.execute(sql)
                except Exception as e:
                    print(f"[-] SQL 执行失败: {e}")
        conn.commit()
        cursor.close()

if __name__ == '__main__':
    sql_path = os.path.join(os.getcwd(), "init.sql")  # 需要执行的 SQL 文件
    try:
        conn = pymysql.connect(**mysql_config)
        print("[+] 成功连接 MySQL 数据库")
        exec_sql_file(conn, sql_path)
        conn.close()
        print("[+] 数据库初始化完成")
    except Exception as e:
        print(f"[-] 无法连接到 MySQL: {e}")
