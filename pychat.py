#!/usr/bin/env python
# coding: utf-8

""" A minimalistic encrypted peer-to-peer chat software. """

import socket
import time
from datetime import datetime
import sys
import os
from base64 import *
import binascii
import signal
import platform
import argparse
import json
import re
import threading
from tkinter import *
import tkinter.scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

__author__ = "Loan Laux"
__copyright__ = "Copyright 2015"
__credits__ = ["Stéphane Ranaivosoa", "Guillaume Liautard", "Bruno Masi"]
__license__ = "MIT"
__maintainer__ = "Loan Laux"
__email__ = "contact@loanlaux.fr"
__status__ = "Development"

# Command-line arguments parsing

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help = "increases command line verbosity", action = "store_true")
parser.add_argument("-e", "--encryption", help = "enables RSA and AES256 encryption", action = "store_true")
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

    if (not args.gui):
        conversation.removeLastLine()

    if args.verbose and (not silent):
        conversation.append("Sending disconnection notice...")

    disconnectionObject = json.dumps({ u"dataType": "status",
        u"username": args.username,
        u"time": time.time(),
        u"status": "disconnected"
    })

    if client:
        connection.send(disconnectionObject.encode('utf-8'))

    else:
        clientConnection.send(disconnectionObject.encode('utf-8'))

    if args.verbose and (not silent):
        conversation.appendCheck()
        conversation.append("Closing socket...")

    connection.close()

    if args.verbose and (not silent):
        conversation.appendCheck()

    else:
        print("")

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
        if os.name == "posix":
            self.content += " ✓"

        else:
            self.content += " Done."

        self.read()

    def appendError(self):
        if os.name == "posix":
            self.content += " ✗"

        else:
            self.content += " Failed."

        self.read()

    def removeLastLine(self):
        self.content = re.sub(r"([^\r\n|\n\r]*)$", "", self.content)[:-1]
        self.read()

    def read(self):
        if os.name == "posix":
            os.system("clear")

        else:
            os.system("cls")

        print(self.content)

conversation = textCanvas()

# AES padding function

def pad(message):
    return message + ((16 - (message.encode().__sizeof__() - 33) % 16) *  '{' )

# Generates RSA public/ private keys and AES passphrase if encryption is enabled

if args.encryption:
    if args.verbose:
        conversation.append("Generating RSA keys...")

    try:
        rsaKey = RSA.generate(2048)
        privateKey = rsaKey.exportKey('PEM')
        publicKey = rsaKey.publickey().exportKey('PEM')

        privateKeyObject = RSA.importKey(privateKey)

        if args.verbose:
            conversation.appendCheck()

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

    if args.verbose:
        conversation.append("Generating AES passphrase...")

    try:
        aesPassphrase = os.urandom(16)
        aesCipher = AES.new(aesPassphrase)

        if args.verbose:
            conversation.appendCheck()

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

# Initializes the 'connection' socket object

if args.verbose:
    conversation.append("Creating socket object...")

connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

if args.verbose:
    conversation.appendCheck()

try:
    if args.verbose and (not closingSocket):
        conversation.append("Trying to connect to " + str(args.host) + ":" + str(args.port) + "...")

    # ...or, if the other end script has already done so, sets itself in client mode

    connection.connect((args.host, args.port))

    if args.verbose:
        conversation.appendCheck()
        conversation.append("Link established!")

    client = True

except:
    if args.verbose:
        conversation.appendError()
        conversation.append("The other end doesn't seem to be waiting for us.")
        conversation.append("Reseting socket...")

    try:
        connection.close()
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if args.verbose:
            conversation.appendCheck()

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

    if args.verbose:
        conversation.append("Binding port " + str(args.port) + "...")

    try:
        connection.bind(('', args.port))

        if args.verbose:
            conversation.appendCheck()

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

    if args.verbose:
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

if (not args.gui) or args.verbose:
    # Output connection info

    conversation.append("Ready to send and receive on port " + str(args.port))

recipientKeyObject = None

def receive():
    global recipientKeyObject
    while True:
        data = None

        try:
            # If set up in client mode, use the standard 'connection' socket object to receive data

            if client:
                data = connection.recv(8192)

            # Otherwise, use the 'clientConnection' socket object, which communicates with the client

            else:
                data = clientConnection.recv(8192)

        except OSError as e:
            if e.errno == 9:
                pass

            else:
                raise

        # If data received

        if data:
            if args.verbose:
                #if not args.gui:
                #    conversation.removeLastLine()

                conversation.append("Got data. Decoding...")

            # Decode it

            data = data.decode("utf-8")

            if args.verbose:
                conversation.appendCheck()

            # Check data type

            if json.loads(data)['dataType'] == "key" or json.loads(data)['dataType'] == "passphrase" or json.loads(data)['dataType'] == "status":
                if not args.encryption:
                    if args.gui:
                        conversationElement.config(state = NORMAL)
                        conversationElement.insert(END, "Recipient is trying to use encryption but it is turned off on your side. \n")
                        conversationElement.yview(END)
                        conversationElement.config(state = DISABLED)

                    else:
                        conversation.append("Recipient is trying to use encryption but it is turned off on your side.")

                # Extract recipient key

                if args.verbose:
                    conversation.append("Received " + str(json.loads(data)['dataType']) + ". Extracting...")

                if json.loads(data)['dataType'] == 'key':
                    try:
                        recipientKey = json.loads(data)['key']
                        recipientKeyObject = RSA.importKey(recipientKey.encode())

                        if args.verbose:
                            conversation.appendCheck()

                    except Exception as e:
                        if args.verbose:
                            conversation.appendError()

                        conversation.append(e)
                        signalHandler(None, None, 1)

                elif json.loads(data)['dataType'] == "status" and json.loads(data)['status'] == "disconnected":
                    if args.gui:
                        conversationElement.config(state = NORMAL)
                        conversationElement.insert(END, datetime.fromtimestamp(json.loads(data)['time']).strftime('%H:%M') + " - " + json.loads(data)['username'] + " just disconnected. \n")
                        conversationElement.yview(END)
                        conversationElement.config(state = DISABLED)

                    else:
                        conversation.append(datetime.fromtimestamp(json.loads(data)['time']).strftime('%H:%M') + " - " + json.loads(data)['username'] + " just disconnected.")

                    if args.verbose:
                        conversation.appendCheck()

                else:
                    try:
                        # RSA decryption

                        global aesPassphrase
                        global aesCipher

                        aesPassphrase = json.loads(data)['passphrase']
                        aesPassphrase = binascii.a2b_qp(aesPassphrase)
                        aesPassphrase = privateKeyObject.decrypt(aesPassphrase)

                        # Decode passphrase and create new cipher object from it

                        aesPassphrase = b64decode(aesPassphrase)
                        aesCipher = AES.new(aesPassphrase)

                        if args.verbose:
                            conversation.appendCheck()

                        if args.gui:
                            conversationElement.config(state = NORMAL)
                            conversationElement.insert(END, "This session is now encrypted. \n")
                            conversationElement.yview(END)
                            conversationElement.config(state = DISABLED)

                        else:
                            conversation.append("This session is now encrypted.")

                        if not args.gui:
                            conversation.append("Message: ")

                    except Exception as e:
                        if args.verbose:
                            conversation.appendError()

                        conversation.append(e)
                        signalHandler(None, None, 1)

            elif json.loads(data)['dataType'] == "message":
                if args.encryption and recipientKeyObject:
                    try:
                        if args.verbose:
                            conversation.append("Decrypting message...")

                        # RSA decryption
                        encryptedMessage = json.loads(data)['message']
                        encryptedMessage = binascii.a2b_qp(encryptedMessage)
                        message = privateKeyObject.decrypt(encryptedMessage)

                        # AES decryption
                        message = aesCipher.decrypt(message).decode("utf-8")
                        l = message.count('{')
                        message = message[:len(message)-l]

                        if args.verbose:
                            conversation.appendCheck()

                    except Exception as e:
                        if args.verbose:
                            conversation.appendError()

                        conversation.append(e)
                else:
                    message = str(json.loads(data)['message'])

                # Output message

                if args.gui:
                    conversationElement.config(state = NORMAL)
                    conversationElement.insert(END, json.loads(data)['username'] + " - " + datetime.fromtimestamp(json.loads(data)['time']).strftime('%H:%M') + " > " + message)
                    conversationElement.yview(END)
                    conversationElement.config(state = DISABLED)

                if not args.gui:
                    if not args.verbose:
                        conversation.removeLastLine()

                    conversation.append(json.loads(data)['username'] + " - " + datetime.fromtimestamp(json.loads(data)['time']).strftime('%H:%M') + " > " + message + "Message:")

        else:
            break

def sendKey():
    if args.verbose:
        conversation.append("Preparing public key JSON object...")

    try:
        publicKeyJsonObject = json.dumps({ u"dataType": u"key",
            u"username": args.username,
            u"time": time.time(),
            u"key": str(publicKey, "utf-8")
        })

        if args.verbose:
            conversation.appendCheck()

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

    try:
        if args.verbose:
            conversation.append("Encoding and sending public key...")

        if client:
            connection.send(publicKeyJsonObject.encode('utf-8'))

        else:
            clientConnection.send(publicKeyJsonObject.encode('utf-8'))

        if args.verbose:
            conversation.appendCheck()

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

def sendPassphrase():
    global aesPassphrase
    global recipientKeyObject

    while not recipientKeyObject:
        pass

    if args.verbose:
        conversation.append("Encrypting AES passphrase...")

    try:

        # Encrypt passphrase
        aesPassphrase = b64encode(aesPassphrase)
        aesPassphrase = recipientKeyObject.encrypt(aesPassphrase, 'x')[0]
        aesPassphrase = str(binascii.b2a_qp(aesPassphrase), 'utf-8')

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

    if args.verbose:
        conversation.append("Preparing AES passphrase JSON object...")

    try:
        publicKeyJsonObject = json.dumps({ u"dataType": u"passphrase",
            u"username": args.username,
            u"time": time.time(),
            u"passphrase": aesPassphrase
        })

        if args.verbose:
            conversation.appendCheck()

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

    try:
        if args.verbose:
            conversation.append("Encoding and sending passphrase...")

        if client:
            connection.send(publicKeyJsonObject.encode('utf-8'))

        else:
            clientConnection.send(publicKeyJsonObject.encode('utf-8'))

        if args.verbose:
            conversation.appendCheck()

        if args.gui:
            conversationElement.config(state = NORMAL)
            conversationElement.insert(END, "This session is now encrypted. \n")
            conversationElement.yview(END)
            conversationElement.config(state = DISABLED)

        else:
            conversation.append("This session is now encrypted.")
            conversation.append("Message:")

    except Exception as e:
        if args.verbose:
            conversation.appendError()

        conversation.append(e)
        signalHandler(None, None, 1)

def send(guiMessage = None):
    if args.encryption and (not guiMessage):
        sendKey()

        if client:
            sendPassphrase()

    if args.gui and guiMessage:
        # Get the message from the function argument

        message = str(guiMessage) + "\n"
        unencryptedMessage = message

        if args.encryption:
            if args.verbose:
                conversation.append("Encrypting message...")

            try:
                # AES encryption
                message = aesCipher.encrypt(pad(message))

                # RSA encryption
                message = recipientKeyObject.encrypt(message, 'x')[0]
                message = str(binascii.b2a_qp(message), "utf-8")

                if args.verbose:
                    conversation.appendCheck()

            except Exception as e:
                if args.verbose:
                    conversation.appendError()

                conversation.append(e)

        if args.verbose:
            conversation.append("Creating message JSON object...")

        # Pack it inside a JSON object, alongside data type, username and sending time

        messageObject = json.dumps({ u"dataType": "message",
            u"username": args.username,
            u"time": time.time(),
            u"message": message
        })

        if args.verbose:
            conversation.appendCheck()
            conversation.append("Encoding and sending message...")

        # Choose the right socket object based on the current configuration (server/client)

        if client:
            connection.send(messageObject.encode('utf-8'))

        else:
            clientConnection.send(messageObject.encode('utf-8'))

        if args.verbose:
            conversation.appendCheck()

        # Output the message locally

        conversationElement.config(state = NORMAL)
        conversationElement.insert(END, json.loads(messageObject)['username'] + " - " + datetime.fromtimestamp(json.loads(messageObject)['time']).strftime('%H:%M') + " > " + unencryptedMessage)
        conversationElement.yview(END)
        conversationElement.config(state = DISABLED)

        # Clear the message field

        messageField.delete(0, 'end')

    elif not args.gui:
        # Output the first prompt message

        if not args.encryption:
            conversation.append("Message: ")

        while True:
            # Read user input

            message = str(sys.stdin.readline())

            conversation.removeLastLine()

            unencryptedMessage = message

            if args.encryption:
                if args.verbose:
                    conversation.append("Encrypting message...")

                try:
                    # AES encryption
                    message = aesCipher.encrypt(pad(message))

                    # RSA encryption
                    message = recipientKeyObject.encrypt(message, 'x')[0]
                    message = str(binascii.b2a_qp(message), "utf-8")

                    if args.verbose:
                        conversation.appendCheck()

                except Exception as e:
                    if args.verbose:
                        conversation.appendError()

                    conversation.append(e)

            if args.verbose:
                conversation.append("Creating message JSON object...")

            # Pack it inside a JSON object, alongside username and sending time

            messageObject = json.dumps({ u"dataType": u"message",
                u"username": args.username,
                u"time": time.time(),
                u"message": message
            })

            if args.verbose:
                conversation.appendCheck()
                conversation.append("Encoding and sending message...")

            # Choose the right socket object based on the current configuration (server/client)

            if client:
                connection.send(messageObject.encode('utf-8'))

            else:
                clientConnection.send(messageObject.encode('utf-8'))

            if args.verbose:
                conversation.appendCheck()

            # Output the message locally

            conversation.append(json.loads(messageObject)['username'] + " - " + datetime.fromtimestamp(json.loads(messageObject)['time']).strftime('%H:%M') + " > " + unencryptedMessage + "Message: ")

# Tkinter GUI configuration

if args.gui:
    # Initialize the window

    window = Tk()
    window.title("PyChat")
    window.resizable(width = False, height = False)
    window.geometry('300x400')

    window.option_add("*Font", "Helvetica")

    # Create message field content object as new StringVar

    messageFieldContent = StringVar()

    # Initialize the conversation text area

    if sys.platform == "darwin":
        conversationElement = tkinter.scrolledtext.ScrolledText(window, height = 24, width = 34)

    elif sys.platform == "linux" or sys.platform == "linux2":
        conversationElement = tkinter.scrolledtext.ScrolledText(window, height = 17, width = 30)

    else:
        conversationElement = tkinter.scrolledtext.ScrolledText(window, height = 20, width = 30)

    conversationElement.grid(row = 0, column = 0, columnspan = 2)
    conversationElement.config(state = DISABLED, wrap = WORD)

    # Same thing for the message field

    messageField = Entry(window, textvariable = messageFieldContent, width = 25)
    messageField.bind("<Return>", lambda event: send(messageFieldContent.get()))
    messageField.grid(row = 1, column = 0)

    # And finally the send button

    if sys.platform == "linux" or sys.platform == "linux2":
        sendButton = Button(window, text = "Envoyer", width = 3, command = lambda: send(messageFieldContent.get()))

    else:
        sendButton = Button(window, text = "Envoyer", width = 6, command = lambda: send(messageFieldContent.get()))
    sendButton.grid(row = 1, column = 1)

if args.gui:
    # If GUI is on, the send function will be called when needed, no need for a loop. So start only the receive loop in a thread.

    receiveThread = threading.Thread(target=receive)
    receiveThread.setDaemon(True)
    receiveThread.start()

    send()

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
