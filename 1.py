import os

test_file_path = os.path.join('D:\\PyCharm\\project\\bishe\\vuln_scan_system\\media', 'test_write.txt')
with open(test_file_path, 'w') as f:
    f.write('测试写入权限')