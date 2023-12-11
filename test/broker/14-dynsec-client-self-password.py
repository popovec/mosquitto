#!/usr/bin/env python3

from mosq_test_helper import *
import json
import shutil

def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener %d\n" % (port))
        f.write("allow_anonymous false\n")
        f.write("plugin ../../plugins/dynamic-security/mosquitto_dynamic_security.so\n")
        f.write("plugin_opt_config_file %d/dynamic-security.json\n" % (port))

def command_check(sock, command_payload, expected_response, msg=""):
    command_packet = mosq_test.gen_publish(topic="$CONTROL/dynamic-security/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(msg)
        print(expected_response)
        print(response)
        raise ValueError(response)

def command_check_self(sock, command_payload, expected_response, msg=""):
    command_packet = mosq_test.gen_publish(topic="$CONTROL/dynamic-security/self/v1", qos=0, payload=json.dumps(command_payload))
    sock.send(command_packet)
    response = json.loads(mosq_test.read_publish(sock))
    if response != expected_response:
        print(msg)
        print(expected_response)
        print(response)
        raise ValueError(response)



port = mosq_test.get_port()
conf_file = os.path.basename(__file__).replace('.py', '.conf')
write_config(conf_file, port)

create_client_command = { "commands": [{
            "command": "createClient", "username": "user_one",
            "password": "password", "clientid": "cid",
            "textname": "Name", "textdescription": "Description",
            "correlationData": "2" }]
}
create_client_response = {'responses': [{'command': 'createClient', 'correlationData': '2'}]}

create_roles_command = { "commands": [
    {
        "command": "createRole", "rolename": "self_password",
        "textname": "Name", "textdescription": "Description",
	"acls":	[
	{"acltype":"publishClientSend",	"topic":"$CONTROL/dynamic-security/self/#", "priority":100, "allow":True},
	{"acltype":"publishClientReceive", "topic":"$CONTROL/dynamic-security/self/#", "priority":100, "allow":True},
	{"acltype":"subscribePattern", "topic":"$CONTROL/dynamic-security/self/#", "priority":100, "allow":True},
	{"acltype":"unsubscribePattern", "topic":"$CONTROL/dynamic-security/self/#", "priority":0, "allow":True}
	], "correlationData": "21" }]
}
create_roles_response = {'responses': [
    {'command': 'createRole', 'correlationData': '21'},
    ]}

add_role_to_client_command = {"commands": [{'command':'addClientRole', "username":"user_one", "rolename":"self_password"}]}
add_role_to_client_response = {'responses': [{'command': 'addClientRole'}]}



change_password_command = {"commands": [{"command":"setSelfPassword", "password":"new_pass"}]}
change_password_response = {'responses': [{'command': 'setSelfPassword'}]}

rc = 1
keepalive = 10

connect_packet = mosq_test.gen_connect("ctrl-test", keepalive=keepalive, username="admin", password="admin")
connack_packet = mosq_test.gen_connack(rc=0)

connect_packet_user1 = mosq_test.gen_connect("cid", keepalive=keepalive, username="user_one", password="password")
connack_packet_user1 = mosq_test.gen_connack(rc=0)

connect_packet_user2 = mosq_test.gen_connect("cid", keepalive=keepalive, username="user_one", password="new_pass")
connack_packet_user2 = mosq_test.gen_connack(rc=0)

mid = 2
subscribe_packet = mosq_test.gen_subscribe(mid, "$CONTROL/#", 1)
suback_packet = mosq_test.gen_suback(mid, 1)

subscribe_packet_user = mosq_test.gen_subscribe(mid, "$CONTROL/dynamic-security/self/#", 1)
suback_packet_user = mosq_test.gen_suback(mid, 1)

try:
    os.mkdir(str(port))
    shutil.copyfile("dynamic-security-init.json", "%d/dynamic-security.json" % (port))
except FileExistsError:
    pass

broker = mosq_test.start_broker(filename=os.path.basename(__file__), use_conf=True, port=port)

try:
    sock = mosq_test.do_client_connect(connect_packet, connack_packet, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet, suback_packet, "suback")

    # Create client
    command_check(sock, create_client_command, create_client_response)

    # Create role
    command_check(sock, create_roles_command, create_roles_response)

    # Add role
    command_check(sock, add_role_to_client_command, add_role_to_client_response)

    # Disconnect
    sock.close()

    # Reconnect as user
    sock = mosq_test.do_client_connect(connect_packet_user1, connack_packet_user1, timeout=5, port=port)
    mosq_test.do_send_receive(sock, subscribe_packet_user, suback_packet_user, "suback")

    # Change password
    command_check_self(sock, change_password_command, change_password_response)

    # Disconnect
    sock.close()

    # Reconnect as user, use new password
    sock = mosq_test.do_client_connect(connect_packet_user2, connack_packet_user2, timeout=5, port=port)

    rc = 0

    sock.close()
except mosq_test.TestError:
    pass
finally:
    os.remove(conf_file)
    try:
        os.remove(f"{port}/dynamic-security.json")
        pass
    except FileNotFoundError:
        pass
    os.rmdir(f"{port}")
    broker.terminate()
    broker.wait()
    (stdo, stde) = broker.communicate()
    if rc:
        print(stde.decode('utf-8'))


exit(rc)
