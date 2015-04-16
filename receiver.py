#!/usr/bin/python

import socket
import sys
import signal

def signalHandler(signal, frame):
    print("\n\nClosing socket...")
    connection.close()
    print("Done.")
    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

try:
    port = int(sys.argv[1])
    host = str(sys.argv[2])

except:
    print("Usage: " + sys.argv[0] + " [port] [host]")
    sys.exit(0)

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.connect((host, port))

while True:
    message = connection.recv(1024)

    if message:
        message = message.decode("utf-8")
        print(message)

signal.pause()
