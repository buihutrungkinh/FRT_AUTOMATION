import paramiko
import ipaddress
import sys

def CONNECTION_WITH_KEY(hostname, username, key):
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            pkey = paramiko.RSAKey.from_private_key_file(key)
            session.connect(hostname=hostname,
                            username=username,
                            port=22,
                            pkey=pkey
                            )
            return session
        except paramiko.AuthenticationException:
            print("Lỗi xác thực. Kiểm tra tên người dùng và mật khẩu.")
        except paramiko.SSHException as e:
            print(f"Lỗi SSH: {e}")
        except Exception as e:
            print(f"Lỗi: {e}")
        return None

def CONNECTION(hostname, username, password):
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            session.connect(
                hostname=hostname,
                username=username,
                password=password,
                port=22,
            )
            return session
        except paramiko.AuthenticationException:
            print("Lỗi xác thực. Kiểm tra tên người dùng và mật khẩu.")
        except paramiko.SSHException as e:
            print(f"Lỗi SSH: {e}")
        except Exception as e:
            print(f"Lỗi: {e}")
        return None

def IS_VALID_IP(IP):
    try:
        ipaddress.ip_address(IP)
        return True
    except ValueError:
        return False
    
def CHECK_EXISTS_NGINX(IP, hostname, username, key):
    if IS_VALID_IP(IP):
        SESSION = CONNECTION_WITH_KEY(hostname, username, key)
        if SESSION:
            print("HOST => {} => Kết nối SSH thành công.".format(hostname))
            stdin, stdout, stderr = SESSION.exec_command('cat /etc/nginx/ip_access_list/allow_ip_hoanmy.conf')
            file_content = stdout.read().decode('utf-8')
            if IP in file_content:
                print("HOST => {} => Đã có IP: {}".format(hostname, IP))
            else:
                print("HOST => {} => Chưa có IP: {}".format(hostname, IP))
            SESSION.close()
        else:
            print("HOST => {} => Kết nối SSH thất bại.".format(hostname))
    else:
        print("IP => {} => Không hợp lệ".format(IP))

def CHECK_EXISTS_APACHE(IP, hostname, username, key):
    if IS_VALID_IP(IP):
        SESSION = CONNECTION_WITH_KEY(hostname, username, key)
        if SESSION:
            print("HOST => {} => Kết nối SSH thành công.".format(hostname))
            stdin, stdout, stderr = SESSION.exec_command('cat /etc/httpd/ip_access_list/allow_ip_hoanmy.conf')
            file_content = stdout.read().decode('utf-8')
            if IP in file_content:
                print("HOST => {} => Đã có IP: {}".format(hostname, IP))
            else:
                print("HOST => {} => Chưa có IP: {}".format(hostname, IP))
            SESSION.close()
        else:
            print("HOST => {} => Kết nối SSH thất bại.".format(hostname))
    else:
        print("IP => {} => Không hợp lệ".format(IP))

def ADD_DHV_NGINX(IP, hostname, username, key):
    if IS_VALID_IP(IP):
        SESSION = CONNECTION_WITH_KEY(hostname, username, key)
        if SESSION:
            print("HOST => {} => Kết nối SSH thành công.".format(hostname))
            command = "sudo bash -c \"echo 'allow {};' >> /etc/nginx/ip_access_list/allow_ip_hoanmy.conf\"".format(IP)
            command2 = "sudo bash -c 'nginx -t'"
            command3 = "sudo bash -c 'systemctl reload nginx'"
            stdin, stdout, stderr = SESSION.exec_command(command)
            print("HOST => {} => allow {};".format(hostname, IP))
            stdin, stdout, stderr = SESSION.exec_command(command2)
            file_content1 = stdout.read().decode('utf-8')
            file_content2 = stderr.read().decode('utf-8')
            if "syntax is ok" in file_content1 or "syntax is ok" in file_content2:
                print("HOST => {} => Syntax successfully".format(hostname))
                stdin, stdout, stderr = SESSION.exec_command(command3)
                status = stdout.channel.recv_exit_status()
                if status == 0:
                    print("HOST => {} => Reload nginx successfully".format(hostname))
                else:
                    print("HOST => {} => Reload nginx failed".format(hostname))
            else:
                print("HOST => {} => Syntax Failed".format(hostname))
            SESSION.close()
        else:
            print("HOST => {} => Kết nối SSH thất bại.".format(hostname))
    else:
        print("IP: {} => Không hợp lệ".format(IP))

def ADD_DHV_APACHE(IP, hostname, username, key):
    if IS_VALID_IP(IP):
        SESSION = CONNECTION_WITH_KEY(hostname, username, key)
        if SESSION:
            print("HOST => {} => Kết nối SSH thành công.".format(hostname))
            command = "sudo bash -c \"echo 'Allow from {}' >> /etc/httpd/ip_access_list/allow_ip_hoanmy.conf\"".format(IP)
            command2 = "sudo bash -c 'httpd -t'"
            command3 = "sudo bash -c 'systemctl reload httpd'"
            stdin, stdout, stderr = SESSION.exec_command(command)
            print("HOST => {} => Allow from {}".format(hostname, IP))
            stdin, stdout, stderr = SESSION.exec_command(command2)
            file_content1 = stdout.read().decode('utf-8')
            file_content2 = stderr.read().decode('utf-8')
            if "Syntax OK" in file_content1 or "Syntax OK" in file_content2:
                print("HOST => {} => Syntax successfully".format(hostname))
                stdin, stdout, stderr = SESSION.exec_command(command3)
                status = stdout.channel.recv_exit_status()
                if status == 0:
                    print("HOST => {} => Reload httpd successfully".format(hostname))
                else:
                    print("HOST => {} => Reload httpd failed".format(hostname))
            else:
                print("HOST => {} => Syntax Failed".format(hostname))
            SESSION.close()
        else:
            print("HOST => {} => Kết nối SSH thất bại.".format(hostname))
    else:
        print("IP: {} => Không hợp lệ".format(IP))

IP = sys.argv[1]
LIST_HOST_DHV = [
    {"host": "10.201.152.68", "service": "nginx"},
    {"host": "10.96.112.14", "service": "nginx"},
    {"host": "10.96.102.37", "service": "httpd"},
]
for HOST in LIST_HOST_DHV:
    hostname = HOST["host"]
    if HOST["service"] == "httpd":
        CHECK_EXISTS_APACHE(IP, hostname, "tamnq3", "./my_key.pem")
    else:
        CHECK_EXISTS_NGINX(IP, hostname, "tamnq3", "./my_key.pem")
