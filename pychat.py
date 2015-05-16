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
import threading
from tkinter import *
import tkinter.scrolledtext

# Command-line arguments parsing

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help = "increases command line verbosity", action = "store_true")
parser.add_argument("-g", "--gui", help = "enables GUI", action = "store_true")
parser.add_argument("host", help = "server IP address", type = str)
parser.add_argument("port", help = "network communication port", type = int)
parser.add_argument("username", help = "chat username to use", type = str)
args = parser.parse_args()

# Function that checks if window exists

def windowExists():
    try:
        window

    except NameError:
        return False

    else:
        return True

# SIGINT signal catcher that closes the socket properly on exit

closingSocket = False

def signalHandler(signal = None, frame = None, silent = None):
    global closingSocket
    closingSocket = True

    if args.verbose and (not silent):
        conversation.append("Closing socket...")

    connection.close()

    if args.verbose and (not silent):
        conversation.appendCheck()

    if args.gui and windowExists():
        window.destroy()

    sys.exit(0)

signal.signal(signal.SIGINT, signalHandler)

# textCanvas object that makes removing lines displayed in the terminal possible

class textCanvas:
    def __init__(self):
        self.content = ""

    def append(self, text):
        if self.content:
            self.content += "\n"

        self.content += str(text)
        self.read()

    def appendToLine(self, text):
        self.content += str(text)
        self.read()

    def appendCheck(self):
        self.content += " ✓"
        self.read()

    def appendError(self):
        self.content += " ✗"
        self.read()

    def removeLastLine(self):
        self.content = re.sub(r"([^\r\n|\n\r]*)$", "", self.content)[:-1]
        self.read()

    def read(self):
        os.system("clear")
        print(self.content)

conversation = textCanvas()

# Initializes the 'connection' socket object

if args.verbose:
    conversation.append("Creating socket object...")

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

if args.verbose:
    conversation.appendCheck()

try:
    if args.verbose:
        conversation.append("Trying to bind port " + str(args.port) + " for host " + args.host + "...")

    connection.bind((args.host, args.port))

    if args.verbose:
        conversation.appendCheck()
        conversation.append("Starting listening...")

    connection.listen(1)

    if args.verbose:
        conversation.appendCheck()
        conversation.append("Waiting for a connection...")

    clientConnection, connectionInfo = connection.accept()

    if args.verbose:
        conversation.appendCheck()
        conversation.append("Link established!")

    client = False

except:
    if args.verbose and (not closingSocket):
        conversation.appendError()
        conversation.append("The other end is already binding. Trying to connect...")

    try:
        # ...or, if the other end script has already done so, sets itself in client mode

        connection.connect((args.host, args.port))

        if args.verbose:
            conversation.appendCheck()
            conversation.append("Link established!")

        client = True

    except OSError as e:
        # If "Bad file descriptor" error is caught when in GUI mode but window still not created, ignore it

        if (e.errno == 9) and closingSocket:
            signalHandler(None, None, 1)

        else:
            raise

if (not args.gui) or args.verbose:
    # Clear screen and output connection info

    os.system("clear")
    conversation.append("Ready to send and receive on port " + str(args.port))
    conversation.read()

def receive():
    while True:
        message = None

        try:
            # If set up in client mode, use the standard 'connection' socket object to receive data

            if client:
                message = connection.recv(2048)

            # Otherwise, use the 'clientConnection' socket object, which communicates with the client

            else:
                message = clientConnection.recv(2048)

        except OSError as e:
            if e.errno == 9:
                pass

            else:
                raise

        # If data received

        if message:
            if args.verbose:
                if not args.gui:
                    conversation.removeLastLine()
                conversation.append("Got message. Decoding...")

            # Decode it

            message = message.decode("utf-8")

            if args.verbose:
                conversation.appendCheck()

            # Output it

            if args.gui:
                conversationElement.config(state = NORMAL)
                conversationElement.insert(END, json.loads(message)['username'] + " - " + datetime.fromtimestamp(json.loads(message)['time']).strftime('%H:%M') + " > " + json.loads(message)['message'])
                conversationElement.yview(END)
                conversationElement.config(state = DISABLED)

            if not args.gui:
                conversation.append(json.loads(message)['username'] + " - " + datetime.fromtimestamp(json.loads(message)['time']).strftime('%H:%M') + " > " + json.loads(message)['message'] + "Message:")
                conversation.read()

        else:
            break

def send(guiMessage = None):
    if args.gui:
        # Get the message from the function argument

        message = str(guiMessage)

        if args.verbose:
            conversation.append("Creating message JSON object...")

        # Pack it inside a JSON object, alongside username and sending time

        messageObject = json.dumps({ u"username": args.username,
            u"time": time.time(),
            u"message": message + "\n"
        })

        if args.verbose:
            conversation.appendCheck()
            conversation.append("Sending message...")

        # Choose the right socket object based on the current configuration (server/client)

        if client:
            connection.send(messageObject.encode('utf-8'))

        else:
            clientConnection.send(messageObject.encode('utf-8'))

        if args.verbose:
            conversation.appendCheck()

        # Output the message locally

        conversationElement.config(state = NORMAL)
        conversationElement.insert(END, json.loads(messageObject)['username'] + " - " + datetime.fromtimestamp(json.loads(messageObject)['time']).strftime('%H:%M') + " > " + json.loads(messageObject)['message'])
        conversationElement.yview(END)
        conversationElement.config(state = DISABLED)

        # Clear the message field

        messageField.delete(0, 'end')

    else:
        # Output the first prompt message

        conversation.append("Message: ")

        while True:
            # Read user input

            message = str(sys.stdin.readline())

            if args.verbose:
                if not args.gui:
                    conversation.removeLastLine()

                conversation.append("Creating message JSON object...")

            # Pack it inside a JSON object, alongside username and sending time

            messageObject = json.dumps({ u"username": args.username,
                u"time": time.time(),
                u"message": message
            })

            if args.verbose:
                conversation.appendCheck()
                conversation.append("Sending message...")

            # Choose the right socket object based on the current configuration (server/client)

            if client:
                connection.send(messageObject.encode('utf-8'))

            else:
                clientConnection.send(messageObject.encode('utf-8'))

            if args.verbose:
                conversation.appendCheck()

            # Output the message locally

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

    conversationElement = tkinter.scrolledtext.ScrolledText(window, height = 24, width = 39)
    conversationElement.grid(row = 0, column = 0, columnspan = 2)
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

    receiveThread = threading.Thread(target=receive)
    receiveThread.setDaemon(True)
    receiveThread.start()

else:
    # Start one loop in a thread, and the other one normally

    if client:
        receiveThread = threading.Thread(target=receive)
        receiveThread.setDaemon(True)
        receiveThread.start()

        send()

    else:
        sendThread = threading.Thread(target=send)
        sendThread.setDaemon(True)
        sendThread.start()

        receive()

if args.gui:
    # If window deletion event catched, call signalHandler() to close the socket and destroy the window

    window.protocol("WM_DELETE_WINDOW", signalHandler)

    # Launch Tkinter's main loop

    window.mainloop()

signal.pause()
