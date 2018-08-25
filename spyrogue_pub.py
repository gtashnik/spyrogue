"""
SpyRogue public version 
Made by Dmitry: https://github.com/gtashnik
Licensed under Mozilla Pablic License v.2

"""

import random 
from random import choice
from re import findall
from re import *
import pyAesCrypt
from pyAesCrypt import encryptFile, decryptFile
from os import remove
from os.path import splitext
import tkinter
from tkinter import * 
import tkinter.messagebox as box 
import tkinter.ttk as ttk
import os 
import time 
from os import system, listdir, mkdir, chdir, getcwd
from time import sleep


window = Tk() 
window.title('SpyRogue by Dmitry') 
window.geometry('500x500+200+100') 



#FUNCTIONS 



def aboutSoft():
	box.showinfo('About SpyRogue', 'Spyrogue can: \n\n- Encrypt and Decrypt text and files\n- Implement and read hidden text in files\n- Install and start a hidden .Onion websites in DarkNet')




def writeIn():
	fileName = entryFile.get() 
	inPuttedText = inputHidMsg.get('1.0', END+ '-1c')  
	if fileName == '' and inPuttedText == '':
		box.showinfo('Fields are emptry', 'Please, fill in filename and text you want to implenent to file')
	else:
		with open(fileName, "ab") as file:
			file.write(inPuttedText.encode(encoding = 'UTF-8'))
		box.showinfo('Text was added', 'Hidden text was written in file: ' + str(fileName))

def readFrom():
	byte = 1
	try:
		nameOfFile = entryFile2.get() 
		with open(nameOfFile, "rb") as file:
			counter = 0
			f = open ( ("hidden_text.txt"), "w", encoding='utf-8' ) 
			while byte:
				byte = file.read(1)
				f.write(str(byte))
				counter+=1
			box.showinfo('Text was read', 'Hidden text was written in file hidden_text.txt that is located in the same folder with this program ')
	except FileNotFoundError:
		box.showerror('File is not found', 'File: ' + str(nameOfFile) + ' 	is not defined. Please, check the name of the file.')
	else:
		box.showinfo('Number of bytes', 'Number of bytes in ' + str(nameOfFile) + ': ' + str(counter) )

		
# END OF HIDDEN TEXT FUNCTIONS


# BCRYPTOR FUNCTIONS 

bMessage = ''

bKey = ''

def regular(text):
	template = r"[0-9]+"
	return findall(template, text)

def bEncrypt(message, key, final=""):
	with open(key) as bKey:
		book = bKey.read()
	for symbolMessage in message:
		listIndexKey = []
		for indexKey, symbolKey in enumerate(book):
			if symbolMessage == symbolKey:
				listIndexKey.append(indexKey)
		try:
			final += str(choice(listIndexKey)) + '/'
		except IndexError: pass
	return final

def bDecrypt(message, key, final=""):
	with open(key) as bKey:
		book = bKey.read()
		for numbers in regular(message):
			for indexKey, symbolKey in enumerate(book):
				if numbers == str(indexKey):
					final += symbolKey
		return final
	
		
def bEncryptFinal():
	bMessage = bcryptInputTxt.get('1.0', END+ '-1c')
	bKey = bcryptInputKey.get()
	if bMessage == '' and bKey == '':
		box.showinfo('Entry fields is empty', 'Please, fill in message and key and try again.')
	else:
		bEncryptedMsg = bEncrypt(bMessage, bKey)
		f = open( ('b_encrypted.txt'), 'w', encoding='utf-8'	) # creatig a file to write encrypted message
		f.write(str(bEncryptedMsg))
		f.close()
		box.showinfo('Bcryptor: message encrypted', 'The message was encrypted and saved into file b_encrypted.txt ' )

def bDecryptFinal():
	bMessage = bcryptInputTxt.get('1.0', END+ '-1c')
	bKey = bcryptInputKey.get()
	if bMessage == '' and bKey == '':
		box.showinfo('Entry fields is empty', 'Please, fill in message and key and try again.')
	else:
		bDecryptedMsg = bDecrypt(bMessage, bKey)
		f = open( ('b_decrypted.txt'), 'w', encoding='utf-8'	) # creatig a file to write encrypted message
		f.write(str(bDecryptedMsg))
		f.close()
		box.showinfo('Bcryptor: message decrypted', 'The message was decrypted and saved into file b_decrypted.txt ' )

def bAbout():
	box.showinfo('How to use Bcryptor', 'Use txt file with text as a key to encrypt and decrypt messages\n\nAvoid charecters x, q and z in messages that are for encrypt. Use small letters and do not use figures and symbols lik 123:)!@ etc.')

#-- END OF BCRYPTOR FUNCTIONS


# AES FILE CRYPTOR FUNCTIONS

def aesEncrypt(file, password, final=""):
	bufferSize = 64*1024
	try:
		encryptFile(str(file), str(file)+".crp", password, bufferSize)
		remove(file)
	except FileNotFoundError: return "[x] File not found!"
	else: 
		box.showinfo('AESCrypt: file was encrypted', 'File was encrypted')

def aesDecrypt(file, password, final=""):
	bufferSize = 64*1024
	try:
		decryptFile(str(file), str(splitext(file)[0]), password, bufferSize)
		remove(file)
	except FileNotFoundError: return "[x] File not found!"
	except ValueError: return "[x] Password is False!"
	else:
		box.showinfo('AESCrypt: file was decrypted', 'File was decrypted')
		
def aesEncryptLaunch():
	aesFile = aesInputFile.get()
	aesPassword = aesinputPassword.get()
	if aesFile == '' or aesPassword == '':
		box.showinfo('Please fill in fields', 'Please, fill in filename and password to encrypt file!')
	else:
		aesEncrypt(aesFile, aesPassword)
		

def aesDecryptLaunch():
	
	aesFile = aesInputFile.get()
	aesPassword = aesinputPassword.get()
	if aesFile == '' or aesPassword == '':
		box.showinfo('Please fill in fields', 'Please, fill in filename and password to decrypt file!')
	else:
		aesDecrypt(aesFile, aesPassword)
	

# -- END OF AES FILE CRYPTOR FUNCTIONS

# .ONION WEBSITE FUNCTIONS 

def installTor():
	dist = ["apt-get install", "pacman -S"]
	prog = ["tor"]
	for distribution in dist:
		for program in prog:
			system("{dist} {prog}".format(dist = distribution, prog = program))

def startTorService():
	system("systemctl start tor.service")
	box.showinfo('Tor started', 'Tor service started.')
	
def enableTorService():
	#system('whois 213.123.0.125')
	system("systemctl enable tor.service")
	box.showinfo('Tor service is on', 'Tor service is enable.')

def createOnionSite():
	htmlTxt = onionIdexInput.get('1.0', END+ '-1c') #getting the HTML index text file
	www = [False,"/var/www/"]
	onion = [False,"/var/www/onion/"]
	main_files = "/var/lib/tor/onion/"
	html_file = [False,"/var/www/onion/index.html"]
	host_file = "/var/lib/tor/onion/hostname"
	key_file = "/var/lib/tor/onion/private_key"
	readme = [False,"README"]
	torrc = [False,"/etc/tor/torrc"]
	string1 = "HiddenServiceDir /var/lib/tor/onion"
	string2 = "HiddenServicePort 80 127.0.0.1:80"
	
	if "www" in listdir("/var/"):
		www[0] = True
	if www[0] == False:
		mkdir(www[1])
		box.showinfo('Directory is created', 'Directory: ' + www[1] + ' is created.' )
	else:
		if "onion" in listdir(www[1]):
			onion[0] = True
		if onion[0] == False:
			mkdir(onion[1])
			box.showinfo('Directory is created', 'Directory: ' + onion[1] + ' is created.' )
		if "index.html" in listdir(onion[1]):
			html_file[0] = True
		if html_file[0] == False:
			OnionHtml = onionIdexInput.get('1.0', END+ '-1c')
			with open(html_file[1],"w") as html:
				html.write(OnionHtml)
				box.showinfo('HTML file is created', 'HTML file: ' + html_file[1] + ' is created.' )
		with open(torrc[1],"r") as tor:
			for string in tor:
				if string == string1 or string == string2:
					torrc[0] = True
					break
		if torrc[0] == False:
			with open(torrc[1],"a") as tor:
				tor.write(string1+"\n"+string2)
				box.showinfo('Stings appended', 'Strings appended in the : ' + torrc[1] + ' file.' )
		system("systemctl start tor.service")
		system("systemctl restart tor.service")
		sleep(1)
		
		with open(host_file,"r") as host:
			hostname = host.read()
			#PRINT MSGBOX
		
		with open(key_file,"r") as key:
			private_key = key.read()
			f = open( ('onion_privkey.txt'), 'w', encoding='utf-8'	) # creatig a file to write encrypted message
			f.write(str(private_key))
			f.close()
		box.showinfo('Private key is saved', 'Private key for your .Onion site is saved in file onion_privkey.txt. Please, keep this file in top secret!')
		
		chdir(onion[1])
		system("python3 -m http.server 80")
		
		box.showinfo('Website is launched', 'Your website in DarkNet is launched. The hostname of site is: ' + str(hostname))

# --- END OF ONION WEBSITE FUNCTIONS
			
	

# ------- END OF FUNCTIONS


# iSERTING GRAPHIC INTERFACE


nb = ttk.Notebook(window)
nb.pack(fill='both', expand='yes')

about = Label(window)
bCrypt = Label(window)
aesCrypt = Label(window)
hiddenText = Label(window)
onion = Label(window)
nb.add(about, text = "About")
nb.add(bCrypt, text='Text Cryptor')
nb.add(aesCrypt, text='File Cryptor')
nb.add(hiddenText, text='HiddenText')
nb.add(onion, text='.Onion')


# ABOUT ELEMENTS---

frameAbout = Frame(about)
frameAbout.pack(fill=BOTH, expand=True)

frameAbout2 = Frame(about)
frameAbout2.pack(side=LEFT)

frameAbout3 = Frame(about)
frameAbout3.pack(fill=BOTH, expand=True)


aboutTxt = Label(frameAbout, text="SpyRogue")
aboutTxt.place(x=0, y=0)
aboutTxt2 = Label(frameAbout, text="Protect your privacy\nCopyright 2018 Dmitry\nhttps://github.com/gtashnik")
aboutTxt2.place(x=0, y=40)
aboutTxt.config(font=("Corier", 25), foreground = ("blue"))

button_about = Button(frameAbout, text = 'About SpyRogue' , width = 20, command=aboutSoft )
button_about.place(x=0, y=100)

button_exit = Button(frameAbout, text = 'Exit program' , width = 20, command=exit)
button_exit.place(x=0, y=130)

# END OF ABOUT ELEMENTS ---

#BEGIN of BOOK CRYPTOR ELEMENTS

bCryptFrame = Frame(bCrypt)
bCryptFrame.pack(fill=BOTH, expand=True)

bCryptLbl = Label(bCryptFrame, text = 'BCryptor')
bCryptLbl.place(x=0, y=0)
bCryptLbl.config(font=("Corier", 16))

bcryptInputTxtLbl = Label(bCryptFrame, text = 'Input text you want to encrypt or decrypt: ')
bcryptInputTxtLbl.place(x=0, y=40)

bcryptInputTxt = Text(bCryptFrame, width=35, height=10)
bcryptInputTxt.place(x=0, y=60)

bcryptKeyLbl = Label(bCryptFrame, text = 'Input name of txt file with keytext (for example key.txt): ')
bcryptKeyLbl.place(x=0, y=220)

bcryptInputKey = Entry(bCryptFrame, width = 30)
bcryptInputKey.place(x=0, y=240)

button_bcryptEncrypt = Button(bCryptFrame, text = 'Encrypt message', width = 28, command=bEncryptFinal)
button_bcryptEncrypt.place(x=0, y=280)

button_bcryptDecrypt = Button(bCryptFrame, text = 'Decrypt message', width = 28, command=bDecryptFinal)
button_bcryptDecrypt.place(x=0, y=310)

button_bAbout = Button(bCryptFrame, text = 'How to use', width = 20, command = bAbout)
button_bAbout.place(x=280, y=100)

#-- END OF BOOK CRYPTOR ELEMENTS


# BEGIN OF AES CRYPT FILE ELEMENTS

aesFrame = Frame(aesCrypt)
aesFrame.pack(fill=BOTH, expand=True)

aesFileNameLbl = Label(aesCrypt, text="AES File Cryptor")
aesFileNameLbl.place(x=0, y=0)
aesFileNameLbl.config(font=('Corier', 16))

aesFIleInputTxtLbl = Label(aesCrypt, text = 'Input the name of the file to encrypt or decrypt:')
aesFIleInputTxtLbl.place(x=0, y=60)

aesInputFile = Entry(aesCrypt, width = 33)
aesInputFile.place(x=0, y=90)

aesinputPasswordLbl = Label(aesCrypt, text="Entec a password to encrypt or decrypt file: ")
aesinputPasswordLbl.place(x=0, y=130)
aesinputPassword = Entry(aesCrypt, width = 33)
aesinputPassword.place(x=0, y=150
)
button_aesEncrypt = Button(aesCrypt, text='Encrypt file', width = 28, command=aesEncryptLaunch)
button_aesEncrypt.place(x=0, y=180)

button_aesDecrypt = Button(aesCrypt, text='Decrypt file', width = 28, command=aesDecryptLaunch)
button_aesDecrypt.place(x=0, y=210)

# END oF AES CRYPT FILE ELEMENTS

# HIDDEN TEXT ELEMENTS 

hiddenFrame = Frame(hiddenText)
hiddenFrame.pack(fill=BOTH, expand=True)

hidTxtWritelbl = Label(hiddenFrame, text = "Write & read hidden text in file")
hidTxtWritelbl.place(x=0, y=0)
hidTxtWritelbl.config(font=("Corier", 16))

hidTxtInputLbl = Label(hiddenFrame, text = "Input name of the file (for example: picture.jpg):")
hidTxtInputLbl.place(x=0, y=40)

entryFile = Entry(hiddenFrame, width=30)
entryFile.place(x=0, y=60)

hidMsgInputLbl = Label(hiddenFrame, text = "Input or paste text you want to hiddenly write in a file: ")
hidMsgInputLbl.place(x=0, y=80)

inputHidMsg = Text(hiddenFrame, width=35, height=10)
inputHidMsg.place(x=0, y=100)

button_insertHidTxt = Button(hiddenFrame, text = "Write in hidden text", width=28, command=writeIn )
button_insertHidTxt.place(x=0, y=250)


entryFileLbl = Label(hiddenFrame, text = "Enter the name of the file to extract hidden text: ")
entryFileLbl.place(x=0, y=300)

entryFile2 = Entry(hiddenFrame, width=30)
entryFile2.place(x=0, y=320)

button_readHidTxt = Button(hiddenFrame, text = "Read hidden text", width=28, command=readFrom )
button_readHidTxt.place(x=0, y=350)

# --- END OF HIDDEN TEXT ELEMENTS


# ONION WEBSITE ELEMENTS

onionFrame = Frame(onion)
onionFrame.pack(fill=BOTH, expand=True)

onionMainLbl = Label(onionFrame, text="Onion website launcher")
onionMainLbl.place(x=0, y=0)
onionMainLbl.config(font=("Corier", 16))

onionIndexLbl = Label(onionFrame, text = "Enter the content of index.html: ")
onionIndexLbl.place(x=0, y=50)

onionIdexInput = Text(onionFrame, width=35, height=10)
onionIdexInput.place(x=0, y=80)

button_startOnion = Button(onionFrame, text="Create .Onion website", width=28, command=createOnionSite)
button_startOnion.place(x=0, y=230)

button_installTor = Button(onionFrame, text="Install Tor", width=20, command=installTor)
button_installTor.place(x=300, y=90)

button_startTor = Button(onionFrame, text="Start Tor Service", width=20, command=startTorService)
button_startTor.place(x=300, y=120)

button_enableTor = Button(onionFrame, text="Enable Tor Service", width=20, command=enableTorService)
button_enableTor.place(x=300, y=150)

#--- END OF ONION WEBSITE ELEMENTS

# ---


window.mainloop() #ENDING THE PROGRAM
