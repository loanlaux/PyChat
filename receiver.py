#!/usr/bin/python

import socket
import sys
import signal
import argparse
import json
from datetime import datetime

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help = "increases command line verbosity", action = "store_true")
parser.add_argument("host", help = "server IP address", type = str)
parser.add_argument("port", help = "network communication port to use", type = int)
parser.add_argument("username", help = "chat username to use", type = str)
args = parser.parse_args()

def signalHandler(signal, frame):
    print("\n\nClosing socket...")
    connection.close()
    print("Done.")
    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.connect((args.host, args.port))

while True:
    message = connection.recv(1024)

    if message:
        message = message.decode("utf-8")
        print(json.loads(message)['username'] + " - " + datetime.fromtimestamp(json.loads(message)['time']).strftime('%H:%M') + " > " + json.loads(message)['message'])

signal.pause()
