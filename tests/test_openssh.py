
def test_hello(sshd, api):
    print(sshd.host_port, api.port)
