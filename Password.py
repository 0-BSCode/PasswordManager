import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import tkinter.font
import random, pyperclip, os, pyAesCrypt

# Handles password generation
Letter = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
Numbers = '0123456789'
password = ''

# Password required to unlock password viewer
# Replace this with a password of your choosing
PASS = 'HelloWorld!'

# Handles password file encryption and decryption
path = 'Pass.txt'
e_path = 'Pass.txt.aes'
bufferSize = 64 * 1024
psswdviewed = False
all_pass = ''


class App():
    def __init__(self, master):
        # Create GUI
        self.master = master
        self.master.geometry('300x400')
        self.master.title('Password Manager')
        self.master.resizable(False, False)
        self.textfont = tk.font.Font(size=30)
        self.ntbk = ttk.Notebook(self.master)

        self.tab1 = ttk.Frame(self.ntbk, relief=tk.RAISED)
        self.ntbk.add(self.tab1, text='Password Generator')
        self.tab11 = tk.Frame(self.tab1)
        self.tab11.grid(column=0, row=0, padx=(10, 0))
        self.tab12 = tk.Frame(self.tab1)
        self.tab12.grid(column=0, row=1, sticky=tk.W, padx=(10, 0))
        self.tab2 = ttk.Frame(self.ntbk)
        self.ntbk.add(self.tab2, text='Password Viewer')
        self.ntbk.pack(expand=1, fill='both')

        self.output = tk.StringVar()
        self.tbox = ttk.Entry(self.tab11, textvariable=self.output, width=12)
        self.tbox['font'] = self.textfont
        self.tbox.grid(row=0, column=1, pady=(20, 0))
        self.btntext = tk.StringVar()
        self.btntext.set('Generate')
        self.btn = ttk.Button(self.tab11, textvariable=self.btntext, command=self.generatePass)
        self.btn.grid(row=1, column=1, pady=(20, 20))
        ttk.Label(self.tab12, text='Settings: ').grid(row=3, sticky=tk.W, padx=(10, 0), pady=(5, 10))
        self.Upper = tk.IntVar()
        self.upcheck = ttk.Checkbutton(self.tab12, text='Uppercase Letters (A-Z)', variable=self.Upper)
        self.upcheck.grid(row=4, column=0, sticky=tk.W, padx=(15, 0), pady=(5, 5))
        self.Lower = tk.IntVar()
        self.lowcheck = ttk.Checkbutton(self.tab12, text='Lowercase Letters (a-z)', variable=self.Lower)
        self.lowcheck.grid(row=5, column=0, sticky=tk.W, padx=(15, 0), pady=(5, 5))
        ttk.Label(self.tab12, text='Symbols: ').grid(row=6, sticky=tk.W, padx=(15, 0), pady=(5, 5))
        self.symbols = tk.StringVar()
        self.symbols.set('~!@#$%^&*+-/.,\{}[]();:')
        self.Symbols = ttk.Entry(self.tab12, textvariable=self.symbols, width=21)
        self.Symbols.grid(row=6, column=0, padx=(80, 0), pady=(5, 5))
        ttk.Label(self.tab12, text='Length: ').grid(row=7, sticky=tk.W, padx=(15, 0), pady=(5, 5))
        self.length = tk.StringVar()
        self.length.set('10')
        self.Length = ttk.Entry(self.tab12, textvariable=self.length, width=3)
        self.Length.grid(row=7, column=0, sticky=tk.W, padx=(70, 0), pady=(5, 5))
        self.add = ttk.Button(self.tab12, text="Save Password", command=lambda: self.createWindow(master))
        self.add.grid(row=8, column=0, sticky=tk.W, pady=(10, 0))

        self.passcheck = tk.StringVar()
        self.unlock = ttk.Entry(self.tab2, textvariable=self.passcheck)
        self.unlock.pack(pady=30)
        self.submit = ttk.Button(self.tab2, text='Submit', command=lambda: self.verifyPassword(self.tab2))
        self.submit.pack()
        self.passtext = ScrolledText(self.tab2)
        self.edit = 1
        self.editBtn = ttk.Button(self.tab2, text='Edit', command=self.editPassword)

        # For adding passwords window
        self.username = tk.StringVar()
        self.savepass = tk.StringVar()

    def generatePass(self):
        '''Generates Password given the parameters'''
        global Letter
        global Numbers
        global password
        password = ''
        characters = str(self.symbols.get()) + Numbers
        if self.Upper.get() == 1:
            characters += Letter
        if self.Lower.get() == 1:
            characters += Letter.lower()
        passlength = int(self.length.get())
        if passlength < 8 or passlength > 20:
            self.output.set('Invalid Length!')
        else:
            for letter in range(passlength):
                index = random.randint(0, len(characters)-1)
                password += characters[index]
            self.output.set(password)
            pyperclip.copy(password)

    def createWindow(self, master):
        '''Create new window for adding passwords'''
        if psswdviewed:
            newwindow = tk.Toplevel(master)
            newwindow.title('Add Password')
            newwindow.geometry('300x150')
            ttk.Label(newwindow, text='Username: ').grid(row=0, column=0, sticky=tk.W, padx=(15, 0), pady=(30, 0))
            ttk.Label(newwindow, text='Password: ').grid(row=1, column=0, sticky=tk.W, padx=(15, 0), pady=(30, 0))
            Username = ttk.Entry(newwindow, textvariable=self.username, width=25)
            Username.grid(row=0, column=1, padx=(20,0), pady=(30,0), sticky=tk.W)
            Password = ttk.Entry(newwindow, textvariable=self.savepass, width=25)
            Password.grid(row=1, column=1, padx=(20, 0), pady=(30, 0), sticky=tk.W)
            SaveBtn = ttk.Button(newwindow, text='Save', command=lambda: self.addPassword(self.username.get(), self.savepass.get()))
            SaveBtn.grid(row=2, column=1, sticky=tk.W, padx=(30,0), pady=(15,0))
        else:
            print("Unlock password viewer before adding any passwords!")

    def addPassword(self, username, password):
        '''Add password to database'''
        global all_pass
        if username == '' or password == '':
            print("Invalid Input")
        else:
            self.passtext['state'] = 'normal'  # Prevents user from altering anything
            self.passtext.insert(tk.END, f'\n{username}: {password}')
            all_pass = self.passtext.get('1.0', tk.END)
            self.passtext['state'] = 'disabled'

        # Clear username and password entries
        self.username.set('')
        self.savepass.set('')

    def verifyPassword(self, master):
        '''Verifies password before revealing encrypted passwords'''
        global PASS
        if str(self.passcheck.get()) == PASS:
            self.unlock.pack_forget()
            self.submit.pack_forget()
            self.showPasswords(master)
        else:
            self.submit.config(text='Try Again!')

    def showPasswords(self, master):
        '''Decrypts AES file and shows passwords'''
        global PASS, path, e_path, psswdviewed
        global bufferSize, all_pass
        # Indicates that passwords have been viewed
        psswdviewed = True
        try:
            with open(path, "w"):  # Create file to decrypt to
                pass
            pyAesCrypt.decryptFile(e_path, path, PASS, bufferSize)
            os.remove(e_path)
        except FileNotFoundError:
            print("No file to decrypt")
            return
        ttk.Label(master, text='Passwords').place(x=120, y=20)
        self.passtext.place(x=0, y=50)
        self.editBtn.place(x=220, y=20)

        with open(path, 'r') as file:
            for line in file:
                self.passtext.insert(tk.END, line)

        all_pass = self.passtext.get('1.0', tk.END)
        self.passtext['state'] = 'disabled'  # Prevents user from altering anything

    def editPassword(self):
        '''Removes password from database'''
        global all_pass
        if self.edit == 1:
            self.edit = 0
            self.passtext['state'] = 'normal'
            self.editBtn.config(text='Save')
        elif self.edit == 0:
            self.edit = 1
            all_pass = self.passtext.get('1.0', tk.END)
            self.passtext['state'] = 'disabled'
            self.editBtn.config(text='Edit')


if __name__ == '__main__':
    window = tk.Tk()
    app = App(window)
    window.mainloop()
    if psswdviewed:  # If passwords were viewed (i.e. file was decrypted), encrypt it
        try:
            with open(e_path, "w") as f:
                pass
            # Write all passwords back to file (including new passwords added)
            with open(path, "w") as f2:
                f2.write(all_pass)
            pyAesCrypt.encryptFile(path, e_path, PASS, bufferSize)
            os.remove(path)
        except OSError:
            print(e_path + " not found")
