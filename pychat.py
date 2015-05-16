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
from tkinter import *

# Command-line arguments parsing

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help = "increases command line verbosity", action = "store_true")
parser.add_argument("-g", "--gui", help = "enables GUI", action = "store_true")
parser.add_argument("host", help = "server IP address", type = str)
parser.add_argument("port", help = "network communication port", type = int)
parser.add_argument("username", help = "chat username to use", type = str)
args = parser.parse_args()

# SIGINT signal catcher that closes the socket properly on exit

def signalHandler(signal, frame):
    print("\n\nClosing socket...")
    connection.close()
    print("Done.")
    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

# textCanvas object that makes removing lines displayed in the terminal possible

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

# Initializes the 'connection' socket object

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    # Either the script sets itself up as a server...

    connection.bind((args.host, args.port))
    connection.listen(5)
    clientConnection, connectionInfo = connection.accept()
    client = False

except:
    # ...or, if the other end script has already done so, sets itself in client mode

    connection.connect((args.host, args.port))
    client = True

if (not args.gui) or args.verbose:
    # Clear screen and output connection info

    os.system("clear")
    conversation.append("Ready to send and receive on port " + str(args.port))
    conversation.read()

def receive():
    while True:
        # If set up in client mode, use the standard 'connection' socket object to receive data

        if client:
            message = connection.recv(1024)

        # Otherwise, use the 'clientConnection' socket object, which communicates with the client

        else:
            message = clientConnection.recv(1024)

        # If data received

        if message:
            # Decode it

            message = message.decode("utf-8")

            # Output it

            if args.gui:
                conversationElement.config(state = NORMAL)
                conversationElement.insert(END, json.loads(message)['username'] + " - " + datetime.fromtimestamp(json.loads(message)['time']).strftime('%H:%M') + " > " + json.loads(message)['message'])
                conversationElement.config(state = DISABLED)

            else:
                conversation.removeLastLine()
                conversation.append(json.loads(message)['username'] + " - " + datetime.fromtimestamp(json.loads(message)['time']).strftime('%H:%M') + " > " + json.loads(message)['message'] + "Message: ")
                conversation.read()

        else:
            break

def send(guiMessage = None):
    if args.gui:
        # Get the message from the function argument

        message = str(guiMessage)

        # Pack it inside a JSON object, alongside username and sending time

        messageObject = json.dumps({ u"username": args.username,
            u"time": time.time(),
            u"message": message + "\n"
        })

        # Choose the right socket object based on the current configuration (server/client)

        if client:
            connection.send(messageObject.encode('utf-8'))

        else:
            clientConnection.send(messageObject.encode('utf-8'))

        # Output the message locally

        conversationElement.config(state = NORMAL)
        conversationElement.insert(END, json.loads(messageObject)['username'] + " - " + datetime.fromtimestamp(json.loads(messageObject)['time']).strftime('%H:%M') + " > " + json.loads(messageObject)['message'])
        conversationElement.config(state = DISABLED)

        # Clear the message field

        messageField.delete(0, 'end')

    else:
        # Output the first prompt message

        conversation.append("Message: ")
        conversation.read()

        while True:
            # Read user input

            message = str(sys.stdin.readline())

            # Pack it inside a JSON object, alongside username and sending time

            messageObject = json.dumps({ u"username": args.username,
                u"time": time.time(),
                u"message": message
            })

            # Choose the right socket object based on the current configuration (server/client)

            if client:
                connection.send(messageObject.encode('utf-8'))

            else:
                clientConnection.send(messageObject.encode('utf-8'))

            # Output the message locally

            conversation.removeLastLine()
            conversation.append(json.loads(messageObject)['username'] + " - " + datetime.fromtimestamp(json.loads(messageObject)['time']).strftime('%H:%M') + " > " + json.loads(messageObject)['message'] + "Message: ")
            conversation.read()

# Tkinter GUI configuration

if args.gui:
    # Initialize the window

    window = Tk()
    window.title('Swagchat')
    window.resizable(width = False, height = False)
    window.geometry('300x400')

    # Create message field content object as new StringVar

    messageFieldContent = StringVar()

    # Initialize the conversation text area

    conversationElement = Text(window, height = 24, width = 30)
    conversationElement.grid(row = 0, column = 0)
    conversationElement.config(state = DISABLED)

    # Same thing for the message field

    messageField = Entry(window, textvariable = messageFieldContent, width = 25)
    messageField.bind("<Return>", lambda event: send(messageFieldContent.get()))
    messageField.grid(row = 1, column = 0)

    # And finally the send button

    sendButton = Button(window, text = "Send", width = 6, command = lambda: send(messageFieldContent.get()))
    sendButton.grid(row = 1, column = 1)

if args.gui:
    # If GUI is on, the send function will be called when needed, no need for a loop. So start only the receive loop in a thread.

    receiveThread = Thread(target=receive)
    receiveThread.setDaemon(True)
    receiveThread.start()

else:
    # Start one loop in a thread, and the other one normally

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

if args.gui:
    window.mainloop()

signal.pause()
