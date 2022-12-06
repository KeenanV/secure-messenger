import paramiko
from paramiko import SSHClient

client = SSHClient()

host = "YOUR_IP_ADDRESS"
username = "YOUR_LIMITED_USER_ACCOUNT"
password = "YOUR_PASSWORD"

client = paramiko.client.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


client.connect(host, username=username, password=password)


stdin, stdout, stderr = client.exec_command('hostname')
print(type(stdin))
print(type(stdout))
print(type(stderr))

# Optionally, send data via STDIN, and shutdown when done
stdin.write('Hello world')
stdin.channel.shutdown_write()

# Print output of command. Will wait for command to finish.
print(f'STDOUT: {stdout.read().decode("utf8")}')
print(f'STDERR: {stderr.read().decode("utf8")}')

# Get return code from command (0 is default for success)
print(f'Return code: {stdout.channel.recv_exit_status()}')

# Because they are file objects, they need to be closed
stdin.close()
stdout.close()
stderr.close()

# Close the client itself
client.close()