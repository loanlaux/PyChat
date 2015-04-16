#!/usr/bin/python

import socket
import time
import sys
import signal

def signalHandler(signal, frame):
    print("\n\nClosing socket...")
    clientConnection.close()
    print("Done.")
    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

try:
    port = int(sys.argv[1])

except:
    print("Usage: " + sys.argv[0] + " [port]")
    sys.exit(0)

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connection.bind(('', port))
connection.listen(5)

clientConnection, connectionInfo = connection.accept()

print("Ready to send on port " + str(port))

while True:
    message = str(input("Message: "))
    clientConnection.send(message.encode("utf-8"))

signal.pause()
