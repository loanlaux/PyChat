#!/usr/bin/python

from tkinter import *
from PIL import Image, ImageTk

window = Tk()
window.title('PyChat')
window.resizable(width = False, height = False)
window.geometry('300x400')

logo = Image.open("graphics/logo.png")
logoElement = ImageTk.PhotoImage(logo)

ip = StringVar()
port = IntVar()

ipField = Entry(window, textvariable = ip, width = 20)
ipField.grid(row = 0, column = 0)

portField = Entry(window, textvariable = port, width = 5)
portField.grid(row = 0, column = 1)



window.mainloop()
