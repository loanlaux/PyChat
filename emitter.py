#!/usr/bin/python

import socket
import time
import sys
import signal
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help = "increases command line verbosity", action = "store_true")
parser.add_argument("port", help = "network communication port", type = int)
parser.add_argument("username", help = "chat username to use", type = str)
args = parser.parse_args()

def signalHandler(signal, frame):
    print("\n\nClosing socket...")
    clientConnection.close()
    print("Done.")
    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connection.bind(('', args.port))
connection.listen(5)

clientConnection, connectionInfo = connection.accept()

print("Ready to send on port " + str(args.port))

while True:
    message = str(input("Message: "))
    messageObject = json.dumps({ u"username": args.username,
        u"time": time.time(),
        u"message": message
    })

    clientConnection.send(messageObject.encode('utf-8'))

signal.pause()
