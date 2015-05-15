#!/usr/bin/python

import socket
import time
from datetime import datetime
import sys
import os
import signal
import argparse
import json
import re
from threading import Thread

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help = "increases command line verbosity", action = "store_true")
parser.add_argument("host", help = "server IP address", type = str)
parser.add_argument("port", help = "network communication port", type = int)
parser.add_argument("username", help = "chat username to use", type = str)
args = parser.parse_args()

def signalHandler(signal, frame):
    print("\n\nClosing socket...")
    connection.close()
    print("Done.")
    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

class textCanvas:
    def __init__(self):
        self.content = ""

    def append(self, text):
        if self.content:
            self.content += "\n"

        self.content += text

    def appendToLine(self, text):
        self.content += text

    def removeLastLine(self):
        self.content = re.sub(r"([^\r\n|\n\r]*)$", "", self.content)[:-1]

    def read(self):
        os.system("clear")
        print(self.content)

conversation = textCanvas()

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    connection.bind(('', args.port))
    connection.listen(5)
    clientConnection, connectionInfo = connection.accept()
    client = False
    print("Server mode")

except:
    connection.connect((args.host, args.port))
    client = True
    print("Client mode")

os.system("clear")
conversation.append("Ready to send and receive on port " + str(args.port))
conversation.read()

def receive():
    while True:
        if client:
            message = connection.recv(1024)

        else:
            message = clientConnection.recv(1024)

        if message:
            message = message.decode("utf-8")
            conversation.removeLastLine()
            conversation.append(json.loads(message)['username'] + " - " + datetime.fromtimestamp(json.loads(message)['time']).strftime('%H:%M') + " > " + json.loads(message)['message'] + "Message: ")
            conversation.read()

        else:
            break

def send():
    conversation.append("Message: ")
    conversation.read()

    while True:
        message = str(sys.stdin.readline())
        messageObject = json.dumps({ u"username": args.username,
            u"time": time.time(),
            u"message": message
        })

        if client:
            connection.send(messageObject.encode('utf-8'))

        else:
            clientConnection.send(messageObject.encode('utf-8'))

        conversation.removeLastLine()
        conversation.append(json.loads(messageObject)['username'] + " - " + datetime.fromtimestamp(json.loads(messageObject)['time']).strftime('%H:%M') + " > " + json.loads(messageObject)['message'] + "Message: ")
        conversation.read()

if client:
    receiveThread = Thread(target=receive)
    receiveThread.setDaemon(True)
    receiveThread.start()
    send()

else:
    sendThread = Thread(target=send)
    sendThread.setDaemon(True)
    sendThread.start()
    receive()

signal.pause()
