"""
Password Manager by Ishan Pro
@author : Ishan Mitra
@license : BSD License
@copyright : Copyright 2021, Ishan Mitra
@email : ishanmitra020@gmail.com
@place : Kolkata
@version : 0.4

@packages used:
tkinter
numpy
functools
random
sqlite
hashlib
pycrpytodome
string
pyperclip
datetime
plyer
pathlib
csv
os

@exe command: 
pyinstaller --onefile --windowed --icon=logo.ico --hidden-import plyer.platforms.win.notification D:\Python\Password\Password_generator.py

@python 3.8.9 32 bit
pyinstaller --onefile --windowed --icon=logo.ico --hidden-import plyer.platforms.win.notification 
--hidden-import requests 
--hidden-import pycryptodome 
--hidden-import pyperclip
--hidden-import pywin32 
--hidden-import Pillow
D:\Python\Password\Password_generator.py
"""
__version__ = '0.4'

from threading import Thread
from tkinter import Frame, Menu, Tk, Entry, Label, Button, Canvas, PhotoImage, Toplevel, messagebox, ttk, filedialog
from requests import get as get_request
from PIL import ImageTk, Image
from functools import partial
from datetime import datetime
from pathlib import Path
import random
import hashlib
import string
from os import rmdir
from os.path import exists
from sqlite3 import connect as sql_connect
from pyperclip import copy
from plyer import notification
from sys import argv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from win32api import ShellExecute
from csv import writer, reader
from requests import post as post_request

BASE_DIR = Path(argv[0]).resolve().parent
ACTIVE = 'active'
BOTH = 'both'
BOTTOM = 'bottom'
HORIZONTAL = 'horizontal'
CENTER = 'center'
LEFT = 'left'
END = 'end'
RIGHT = 'right'
VERTICAL = 'vertical'
Y = 'y'
NORMAL = 'normal'
DISABLED = 'disabled'

def decrypt_text_key(message, key):
    try:
        cipher = AES.new(hashlib.sha256().digest(), AES.MODE_CBC, key)
        return unpad(unpad(unpad(unpad(cipher.decrypt(message), AES.block_size), AES.block_size), AES.block_size), AES.block_size).decode()
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

def encrypt_text(message):
    try:
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1')
        pasdf = cursor.fetchone()
        password = bytes(decrypt_text_(pasdf[1]), 'utf-8')
        cipher = AES.new(hashlib.sha256().digest(), AES.MODE_CBC, password[:16])
        return (cipher.encrypt(pad(pad(pad(pad(message, AES.block_size), AES.block_size), AES.block_size), AES.block_size)))
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

def encrypt_text_(message):
    try:
        cipher = AES.new(hashlib.sha256().digest(), AES.MODE_CBC, b'\xc7\xd6\xac*\xe5\x91\xa77\xebu$\x99+\xc2H\xae')
        return cipher.encrypt(pad(pad(pad(pad(message, AES.block_size), AES.block_size), AES.block_size), AES.block_size))
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

def decrypt_text_(message):
    try:
        cipher = AES.new(hashlib.sha256().digest(), AES.MODE_CBC, b'\xc7\xd6\xac*\xe5\x91\xa78\xebu$\x99+\xb2H\xae')
        return unpad(unpad(unpad(unpad(cipher.decrypt(message), AES.block_size), AES.block_size), AES.block_size), AES.block_size).decode()
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")


def decrypt_text(message):
    try:
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1')
        pasdf = cursor.fetchone()
        password = bytes(decrypt_text_(pasdf[1]), 'utf-8')
        cipher = AES.new(hashlib.sha256().digest(), AES.MODE_CBC, password[:16])
        return unpad(unpad(unpad(unpad(cipher.decrypt(message), AES.block_size), AES.block_size), AES.block_size), AES.block_size).decode()
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

def connect():
    global cursor, db
    #db = sql_connect(f'{BASE_DIR}\\lib\\tcl\\msgs\\zn_ah.msg')
    db = sql_connect(f'{BASE_DIR}\\db.db')
    cursor = db.cursor()


    cursor.execute("PRAGMA key='test'")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS masterpassword(
        id INTEGER PRIMARY KEY,
        password TEXT NOT NULL,
        email TEXT NOT NULL);
        """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        notes TEXT NOT NULL);
        """)

    if exists(BASE_DIR / 'temp\\') == True:
        rmdir(BASE_DIR / 'temp\\')



def reset_password(window):
    try:
        for widget in window.winfo_children():
            widget.destroy()
        window.title("Password Manager")
        window.iconbitmap("logo.ico")
        window.config(padx=50, pady=50)
        window.resizable(0, 0)
        canvas = Canvas(height=200, width=200)
        #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
        logo_img = PhotoImage(file="./logo.png")
        canvas.create_image(100, 100, image=logo_img)
        canvas.grid(row=0, column=0)

        lbl = Label(window, text="Choose a Master Password", font=("Helvetica", 18))
        lbl.grid(row=0, column=1)

        txt = Entry(window, width=20, font=("Helvetica", 15))
        txt.grid(row=1, column=1)
        txt.focus()

        lbl1 = Label(window, text="Re-enter password", font=("Helvetica", 15))
        lbl1.grid(row=2, column=1)

        txt1 = Entry(window, width=20, font=("Helvetica", 15))
        txt1.grid(row=3, column=1)
        def focus_txt(*args):
            txt1.focus()
        txt.bind("<Return>", focus_txt)


        def changePassword(*args):
            try:
                cursor.execute('SELECT * FROM masterpassword WHERE id = 1')
                pasdf = cursor.fetchone()
                password_key__ = bytes(decrypt_text_(pasdf[1]), 'utf-8')
                
                cursor.execute("""SELECT id, password, notes FROM vault""")
                notes_and_password = cursor.fetchall()

                if txt.get() == txt1.get():
                    cursor.execute("""UPDATE masterpassword SET
                    password = :password
                    WHERE
                    id = 1""",
                    {
                        'password' : encrypt_text_(bytes(hash_password(txt.get().encode('utf-8')), 'utf-8'))
                    })

                db.commit()

                for passwords in notes_and_password:
                    password_entry_ = decrypt_text_key(passwords[1], password_key__[:16])
                    notes_entry_ = decrypt_text_key(passwords[2], password_key__[:16])
                    cursor.execute("""UPDATE vault SET
                    password = :password,
                    notes = :notes
                    WHERE
                    id = :id""",
                    {
                    'password' : encrypt_text(bytes(password_entry_, 'utf-8')),
                    'notes' : encrypt_text(bytes(notes_entry_, 'utf-8')),
                    'id' : passwords[0]})
                db.commit()
                
                messagebox.showinfo(title="Master password reset sucessfully", message="Master password reset sucessfully")
                vaultScreen(window_var)
            except Exception as E:
                with open('logs.log', 'a') as log_file:
                    log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                    log_file.close()
                    messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

        txt1.bind("<Return>", changePassword)
        btn = Button(window, text="Save", command=changePassword, font=("Helvetica", 15))
        btn.grid(row=5, column=1)

        window.mainloop()

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")



def export_csv():
    try:
        file_path = filedialog.asksaveasfile(title="Save Export CSV File",filetypes = (("CSV files", "*.csv"),))
        if file_path.name.endswith('.csv'):
            file_path_var = file_path.name
        else:
            file_path_var = file_path.name + '.csv'
        try:
            with open(file_path_var, 'w', newline="") as datafile:
                writer_cursor = writer(datafile, dialect='excel')
                cursor.execute('SELECT * FROM vault')
                queries = cursor.fetchall()
                i = 0
                for query in queries:
                    i = i + 1
                    writer_cursor.writerow((i,
                    query[1], 
                    query[2], 
                    query[3], 
                    decrypt_text(query[4]), 
                    decrypt_text(query[5])
                    ))
                messagebox.showinfo(title="Your passwords have been exported", message="Your passwords have been exported")
        except:
            pass

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")



def import_csv():
    try:
        file_path = filedialog.askopenfile(title="Import CSV File",filetypes = (("CSV files", "*.csv"),))
        if file_path.name.endswith('.csv'):
            file_path_var = file_path.name
        else:
            file_path_var = file_path.name + '.csv'
        try:
            with open(file_path_var, 'r', newline="") as data_file:
                reader_cursor = reader(data_file, dialect='excel')
                insert_fields = """INSERT INTO vault(name, website, username, password, notes)
                VALUES(?, ?, ?, ?, ?) """
                for rwo in reader_cursor:
                    cursor.execute(insert_fields, (rwo[1], rwo[2], rwo[3], encrypt_text(bytes(rwo[4], 'utf-8')), encrypt_text(bytes(rwo[5], 'utf-8'))))
                    db.commit()
                vaultScreen(window_var)
                messagebox.showinfo(title="Your passwords have been imported", message="Your passwords have been imported")
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
        
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")
    


def on_closing():
    try:
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            window_var.destroy()
            cursor.close()
            db.close()
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

def hash_password(input: str):
    try:
        return hashlib.sha512(hashlib.sha256(input).hexdigest()).hexdigest()
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")


def firstTimeScreen(window):
    try:
        window.title("Password Manager")
        window.iconbitmap("logo.ico")
        window.config(padx=50, pady=50)
        window.resizable(0, 0)
        canvas = Canvas(height=200, width=200)
        #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
        logo_img = PhotoImage(file="./logo.png")
        canvas.create_image(100, 100, image=logo_img)
        canvas.grid(row=0, column=0)

        email_first_label = Label(window, text="Enter your email", font=("Helvetica", 15))
        email_first_label.grid(row=0, column=1)

        email_first_entry = Entry(window, width=20, font=("Helvetica", 15))
        email_first_entry.grid(row=1, column=1)
        email_first_entry.focus()

        lbl = Label(window, text="Choose a Master Password", font=("Helvetica", 15))
        lbl.grid(row=2, column=1)

        txt = Entry(window, width=20, font=("Helvetica", 15))
        txt.grid(row=3, column=1)
        def focus_password(*args):
            txt.focus()
        email_first_entry.bind("<Return>", focus_password)

        lbl1 = Label(window, text="Re-enter password", font=("Helvetica", 15))
        lbl1.grid(row=4, column=1)

        txt1 = Entry(window, width=20, font=("Helvetica", 15))
        txt1.grid(row=5, column=1)
        def focus_txt(*args):
            txt1.focus()
        txt.bind("<Return>", focus_txt)


        def savePassword(*args):
            try:
                if txt.get() == txt1.get() and '@' in email_first_entry.get() and '.' in email_first_entry.get() and len(email_first_entry.get()) > 3:
                    hashedPassword = encrypt_text_(bytes(hash_password(txt.get().encode('utf-8')), 'utf-8'))
                    hashedemail = encrypt_text_(bytes(hash_password(email_first_entry.get().encode('utf-8')), 'utf-8'))

                    cursor.execute("""INSERT INTO masterpassword(password, email)
                    VALUES(?, ?) """, [(hashedPassword), (hashedemail)])
                    db.commit()

                    login(window_var)
                elif txt.get() != txt1.get():
                    messagebox.showerror(title="Passwords don't match", message="Passwords don't match")
                elif '@' not in email_first_entry.get() or '.' not in email_first_entry.get():
                    messagebox.showerror(title="Invalid email address", message="Invalid email address")
                else:
                    messagebox.showerror(title="Error!", message="Error")
            except Exception as E:
                with open('logs.log', 'a') as log_file:
                    log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                    log_file.close()
                    messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

        txt1.bind("<Return>", savePassword)
        btn = Button(window, text="Save", command=savePassword, font=("Helvetica", 15))
        btn.grid(row=6, column=1)

        window.mainloop()

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")


# ------------------------------------------------------------------ LOGIN WINDOW -------------------------------------------------------------------- #

def forgot_password(window):
    
    def get_otp():
        global resp
        cursor.execute("SELECT email FROM masterpassword")
        email = cursor.fetchone()
        if encrypt_text_(bytes(hash_password(email_master.get().encode('utf-8')), 'utf-8')) == email[0]:
            ask = messagebox.askokcancel(title="Note: Your email address will be stored temporarily on our server to send you the otp, so make sure that you are connected to the internet",
            message="Note: Your email address will be stored temporarily on our server to send you the otp, so make sure that you are connected to the internet")
            if ask == True:
                try:
                    resp = post_request("https://mitraelectronics.herokuapp.com/otp/verify/django/password-manager-by-ishan/root/6/otp/verify", {'email':email_master.get(),'auth':'auth'})
                    otp_submit.config(state=ACTIVE)
                except:
                    messagebox.showerror(title="Error", message="Error")
        else:
            print(email)
            messagebox.showerror(title="Please enter correct email address", message="Please enter correct email address")
    def confirm_otp(*args):
        try:
            otp_var = otp_entry.get()
            actua_otp = resp.text
            actual_otp = actua_otp.replace("Error : ", "")
            if "Server Error" in actual_otp:
                messagebox.showerror("Server Error")
            elif otp_var == actual_otp:
                global txt67, txt16
                for widget in window.winfo_children():
                    widget.destroy()
                window.title("Password Manager")
                window.iconbitmap("logo.ico")
                window.config(padx=50, pady=50)
                window.resizable(0, 0)
                gcanvas = Canvas(height=200, width=200)
                #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
                logo_img = PhotoImage(file="./logo.png")
                gcanvas.create_image(100, 100, image=logo_img)
                gcanvas.grid(row=0, column=0)
                lbl = Label(window, text="Choose a Master Password", font=("Helvetica", 18))
                lbl.grid(row=0, column=1)

                txt67 = Entry(window, width=20, font=("Helvetica", 15))
                txt67.grid(row=1, column=1)
                txt67.focus()

                lbl1 = Label(window, text="Re-enter password", font=("Helvetica", 15))
                lbl1.grid(row=2, column=1)

                txt16 = Entry(window, width=20, font=("Helvetica", 15))
                txt16.grid(row=3, column=1)
                def focus_txt(*args):
                    txt16.focus()
                txt67.bind("<Return>", focus_txt)

                def changePassword(*args):
                    try:
                        cursor.execute('SELECT * FROM masterpassword WHERE id = 1')
                        pasdf = cursor.fetchone()
                        password_key__ = bytes(decrypt_text_(pasdf[1]), 'utf-8')
                        cursor.execute("""SELECT id, password, notes FROM vault""")
                        notes_and_password = cursor.fetchall()

                        if txt67.get() == txt16.get():
                            cursor.execute("""UPDATE masterpassword SET
                            password = :password
                            WHERE
                            id = 1""",
                            {
                                'password' : encrypt_text_(bytes(hash_password(txt67.get().encode('utf-8')), 'utf-8'))
                            })

                        db.commit()

                        for passwords in notes_and_password:
                            password_entry_ = decrypt_text_key(passwords[1], password_key__[:16])
                            notes_entry_ = decrypt_text_key(passwords[2], password_key__[:16])
                            cursor.execute("""UPDATE vault SET
                            password = :password,
                            notes = :notes
                            WHERE
                            id = :id""",
                            {
                            'password' : encrypt_text(bytes(password_entry_, 'utf-8')),
                            'notes' : encrypt_text(bytes(notes_entry_, 'utf-8')),
                            'id' : passwords[0]})
                        db.commit()
                        
                        messagebox.showinfo(title="Master password reset sucessfully", message="Master password reset sucessfully")
                        vaultScreen(window_var)
                    except Exception as E:
                        with open('logs.log', 'a') as log_file:
                            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                            log_file.close()
                            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")


                txt16.bind("<Return>", changePassword)
                btn = Button(window, text="Save", command=changePassword, font=("Helvetica", 15))
                btn.grid(row=5, column=1)

            else:
                messagebox.showerror(title="Invalid otp", message="Invalid OTP")
            
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    try:
        for widget in window.winfo_children():
            widget.destroy()
        window.title("Password Manager")
        window.iconbitmap("logo.ico")
        window.config(padx=50, pady=50)
        window.resizable(0, 0)
        canvas = Canvas(height=200, width=200)
        #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
        logo_img = PhotoImage(file="./logo.png")
        canvas.create_image(100, 100, image=logo_img)
        canvas.grid(row=0, column=0)

        email_master_label = Label(window, text="Enter Email", font=("Helvetica", 18))
        email_master_label.grid(row=0, column=1)

        email_master = Entry(window, width=20, font=("Helvetica", 15))
        email_master.grid(row=1, column=1)
        email_master.focus()
        def email_bind(*args):
            get_otp()
        email_master.bind("<Return>", email_bind)

        oemail_submit = Button(window, text="Get OTP",command=get_otp, font=("Helvetica", 15))
        oemail_submit.grid(row=2, column=1)

        otp_label = Label(window, text="Enter OTP", font=("Helvetica", 15))
        otp_label.grid(row=3, column=1)

        otp_entry = Entry(window, width=20, font=("Helvetica", 15))
        otp_entry.grid(row=4, column=1)
        otp_entry.bind("<Return>", confirm_otp)

        otp_submit = Button(window, text="Submit OTP",command=confirm_otp,state=DISABLED, font=("Helvetica", 15))
        otp_submit.grid(row=5, column=1)

        window.mainloop()

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

def login(window):
    try:
        window.title("Password Manager")
        window.iconbitmap("logo.ico")
        window.config(padx=50, pady=50)
        window.resizable(0, 0)

        for widget in window.winfo_children():
            widget.destroy()

        header = Label(window, text="Created by Ishan Mitra", font=("Lucida Calligraphy", 24))
        header.grid(row=0, column=0)
        footer = Label(window, text="Mitra Electronics and Software, Inc", font=("Kunstler Script", 36, ))
        footer.grid(row=1, column=0)
        header.config(fg="red")

        canvas = Canvas(height=200, width=200)
        logo_img = PhotoImage(file=BASE_DIR/"logo.png")
        canvas.create_image(100, 100, image=logo_img)
        canvas.grid(row=2, column=0)

        email_login_label = Label(window, text="Enter your email", font=("Helvetica", 15))
        email_login_label.grid(row=3, column=0)

        email_login_entry = Entry(window, width=30, font=("Helvetica", 15))
        email_login_entry.grid(row=4, column=0)
        email_login_entry.focus()

        lbl = Label(window, text="Enter Master Password", font=("Helvetica", 15))
        lbl.config(anchor=CENTER)
        lbl.grid(row=5, column=0)

        def getMasterPassword():
            if '@' in email_login_entry.get() and '.' in email_login_entry.get() and len(email_login_entry.get()) > 3:
                check_hashed_password = encrypt_text_(bytes(hash_password(txt.get().encode('utf-8')), 'utf-8'))
                check_hashed_email = encrypt_text_(bytes(hash_password(email_login_entry.get().encode('utf-8')), 'utf-8'))
                cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ? AND email = ?', [(check_hashed_password), (check_hashed_email)])
                return cursor.fetchall()
            else:
                messagebox.showerror(title="Invalid email address", message="Invalid email address")
                return "Error"

        def checkPassword(*args):
            master_password_get = getMasterPassword()
            if master_password_get == "Error":
                pass
            elif master_password_get:
                vaultScreen(window_var)
                with open('logs.log', 'a') as log_file:
                    log_file.write(str(datetime.now()) + " : " + "Logged in sucessfully" + "\n")
                    log_file.close()
            else:
                email_login_entry.delete(0, 'end')
                txt.delete(0, 'end')
                print(master_password_get)
                messagebox.showerror(title="Wrong credentials",message="Please enter your correct credentials")
                with open('logs.log', 'a') as log_file:
                    log_file.write(str(datetime.now()) + " : " + "Couldn't log in due to wrong password" + "\n")
                    log_file.close()

        txt = Entry(window, width=30, font=("Helvetica", 15))
        txt.grid(row=6, column=0)
        def focus_password(*args):
            txt.focus()
        email_login_entry.bind("<Return>", focus_password)
        txt.bind("<Return>", checkPassword)

        btn = Button(window, text="Submit", command=checkPassword, font=("Helvetica", 15))
        btn.grid(row=6, column=3)

        forgot = Button(window, text="Forgot Password?", command=partial(forgot_password, window_var), font=("Helvetica", 15))
        forgot.grid(row=7, column=0)

        window.mainloop()

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

def search(*args):
    def removeEntry(input: int):
        try:
            ask_delete = messagebox.askyesno("Delete Entry", "Do you really want to delete the password?")
            if ask_delete == True:
                cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
                db.commit()
                vaultScreen(window_var)
                messagebox.showinfo(title="Password Deleted Sucessfully", message="Password Deleted Sucessfully")
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def copyf(input: int):
        try:
            cursor.execute('SELECT password FROM vault WHERE ID = ?', (input,))
            array = cursor.fetchone()
            copy(decrypt_text(array[0]))
            notification.notify(
 			    title = "Password copied to clipboard",
 			    message ="Password copied to clipboard!",
                app_name="Password Generator in Python",
 			    app_icon = "logo.ico",
 			    timeout= 5,
                toast=True,
 			    )
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def update_password(i):
        try:
            cursor.execute("""UPDATE vault SET
            name = :name,
            website = :website,
            username = :username,
            password = :password,
            notes = :notes
            WHERE
            id = :id""",
            {
            'name' : name_entry_edit.get(),
            'website' : website_entry_edit.get(),
            'username' : email_entry_edit.get(),
            'password' : encrypt_text(bytes(password_entry_edit.get(), 'utf-8')),
            'notes' : encrypt_text(bytes(notes_entry_edit.get(), 'utf-8')),
            'id' : i[0]
            })
            db.commit()
            vaultScreen(window_var)

        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def see_notes(note):
        try:
            messagebox.showinfo(title="Notes",message=decrypt_text(note))
        
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def change_entry(input):
        global website_entry_edit, email_entry_edit, password_entry_edit, name_entry_edit, notes_entry_edit
        try:
            cursor.execute('SELECT * FROM vault WHERE ID = ?', (input,))
            array = cursor.fetchall()
            window_ = Toplevel()
            for widget in window_.winfo_children():
                widget.destroy()
            window_.title("Change entry")
            #window.iconbitmap(BASE_DIR / "logo.ico")
            window_.iconbitmap("logo.ico")
            window_.geometry('550x400')
            window_.config(padx=50, pady=50)
            window_.resizable(0, 0)

            canvas = Canvas(window_, height=200, width=200)
            #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
            logo_img = PhotoImage(file="logo.png")
            canvas.create_image(100, 100, image=logo_img)
            canvas.grid(row=0, column=1)

            # labels
            name_label = Label(window_, text="Name :")
            name_label.grid(row=1, column=0)

            website_label = Label(window_, text="Website :")
            website_label.grid(row=2, column=0)

            email_label = Label(window_, text="Email/Username :")
            email_label.grid(row=3, column=0)

            password_label = Label(window_, text="Password :")
            password_label.grid(row=4, column=0)

            notes_label = Label(window_, text="Notes :")
            notes_label.grid(row=5, column=0)

            # Entries
            name_entry_edit = Entry(window_, width=53)
            name_entry_edit.grid(row=1, column=1, columnspan=2)
            name_entry_edit.insert(0, (array[0][1]))

            website_entry_edit = Entry(window_, width=53)
            website_entry_edit.grid(row=2, column=1, columnspan=2)
            website_entry_edit.insert(0, (array[0][2]))
            website_entry_edit.focus()

            email_entry_edit = Entry(window_, width=53)
            email_entry_edit.grid(row=3, column=1, columnspan=2)
            email_entry_edit.insert(0, (array[0][3]))

            password_entry_edit = Entry(window_, width=35)
            password_entry_edit.grid(row=4, column=1)
            password_entry_edit.insert(0, decrypt_text(array[0][4]))

            notes_entry_edit = Entry(window_, width=35)
            notes_entry_edit.grid(row=5, column=1)
            notes_entry_edit.insert(0, decrypt_text(array[0][5]))

            # Buttons
            generate_passwordG = Button(window_, text="Generate Password", width=14, command=partial(generate_password, password_entry_edit))
            generate_passwordG.grid(row=4, column=2)
            add_button = Button(window_, text="Update", width=36, command=partial(update_password, array[0]))
            add_button.grid(row=6, column=1, columnspan=2)

            window_var.mainloop()

        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")


    try:
        windowx = Toplevel()
        frame_canvas = Frame(windowx)
        frame_canvas.pack(fill=BOTH, expand=1)
        frame_canvas.rowconfigure(0,weight=1)
        frame_canvas.columnconfigure(0,weight=1)

        canvas = Canvas(frame_canvas)
        canvas.pack(side=LEFT,fill=BOTH, expand=1)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            
        hsb = ttk.Scrollbar(frame_canvas, orient=HORIZONTAL, command=canvas.xview)
        hsb.pack(side=BOTTOM, fill=BOTH)
        canvas.configure(xscrollcommand=hsb.set)
            
        vsb = ttk.Scrollbar(frame_canvas, orient=VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
            
        vsb = ttk.Scrollbar(frame_canvas, orient=VERTICAL, command=canvas.yview)
        vsb.pack(side=RIGHT, fill=Y)
        vsb.state()
        canvas.configure(yscrollcommand=vsb.set)
            
            # Create a frame to contain the buttons
        window = Frame(canvas)
        canvas.create_window((0, 0), window=window, anchor='nw')
        window.bind_all("<MouseWheel>", _on_mousewheel)
        window.bind("<Configure>", lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        window.bind("<Configure>", lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        window.bind("<Configure>", lambda e:canvas.configure(scrollregion=canvas.bbox("all")))

        windowx.geometry('1200x600')
        windowx.config(padx=5, pady=5)
        windowx.resizable(height=0, width=200)
        search_bar = Entry(window)
        search_bar.grid(row=0, column=0)
        def query_search(*args):
            search_term = search_bar.get()
            cursor.execute("SELECT * FROM vault WHERE username = ?", [search_term])
            search_results = cursor.fetchall()

            for widget in window.winfo_children:
                widget.destroy

            lbl = Label(window, text="Sl. no.")
            lbl.grid(row=2, column=0, padx=20)

            lbl = Label(window, text="Name")
            lbl.grid(row=2, column=1, padx=80)

            lbl = Label(window, text="Website")
            lbl.grid(row=2, column=2, padx=80)

            lbl = Label(window, text="Email or Username")
            lbl.grid(row=2, column=3, padx=80)

            lbl = Label(window, text="Password")
            lbl.grid(row=2, column=4, padx=80)
            if search_results != []:
                try:
                    i = 0
                    for ayy in search_results:
                        lbl0 = Label(window, text=(ayy[1]), font=("Helvetica", 12))
                        lbl0.grid(column=1, row=(i+3))

                        lbl00 = Label(window, text=(i+1), font=("Helvetica", 12))
                        lbl00.grid(column=0, row=(i+3))

                        lbl1 = Label(window, text=(ayy[2]), font=("Helvetica", 12))
                        lbl1.grid(column=2, row=(i+3))

                        lbl2 = Label(window, text=(ayy[3]), font=("Helvetica", 12),)
                        lbl2.grid(column=3, row=(i+3))

                        lbl3 = Label(window, text=(decrypt_text(ayy[4])), font=("Helvetica", 12))
                        lbl3.grid(column=4, row=(i+3))

                        copy_btn = Button(window, text="Copy", command=partial(copyf, ayy[0]))
                        copy_btn.grid(column=6, row=(i+3), pady=10)

                        btn = Button(window, text="Delete", command=partial(removeEntry, ayy[0]))
                        btn.grid(column=5, row=(i+3), pady=10)

                        btn_c = Button(window, text="Edit", command=partial(change_entry, ayy[0]))
                        btn_c.grid(column=7, row=(i+3), pady=10)

                        btn_n = Button(window, text="See notes", command=partial(see_notes, ayy[5]))
                        btn_n.grid(column=8, row=(i+3), pady=10)

                        i = i +1

                        cursor.execute('SELECT * FROM vault')
                        if (len(cursor.fetchall()) <= i):
                            break
                        window.update()

                except Exception as E:
                    with open('logs.log', 'a') as log_file:
                        if str(E) == 'list index out of range':
                            pass
                        else:
                            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                            log_file.close()
        search_bar.bind("<Return>", query_search)
        
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

# --------------------------------------------------------------------------- PASSWORD GENERATOR --------------------------------------------------------------- #
def generate_password(password_entry__):
    try:
        password_letters = [random.choice(string.ascii_letters) for _ in range(random.randint(8, 10))]
        password_symbols = [random.choice(string.punctuation) for _ in range(random.randint(2, 4))]
        password_numbers = [random.choice(string.digits) for _ in range(random.randint(2, 4))]
        PASSWORD = password_letters + password_numbers + password_symbols
        random.shuffle(PASSWORD)
        password = "".join(PASSWORD)
        password_entry__.delete(0, END)
        password_entry__.insert(0, password)
        copy(password)
        notification.notify(
                title = "Password copied to clipboard",
                message ="The generated password has been copied to clipboard. Now you change the password to the generated password and stay secure.",
                app_name="Password Manager by Ishan Python",
                app_icon = "logo.ico",
                timeout= 5,
                toast=True,
                )

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

# --------------------------------------------------------------------------------- SAVE PASSWORD ---------------------------------------------------------------------------- #
def save(*args):
    try:
        website = website_entry.get()
        email = email_entry.get()
        password = encrypt_text(bytes(password_entry.get(), 'utf-8'))
        name = (name_entry.get())
        notes = encrypt_text(bytes(notes_entry.get(), 'utf-8'))

        if len(name) == 0 or len(password) == 0 or len(email) == 0:
            messagebox.showinfo(title="Oops", message="Please make sure that each and every field is filled up")
            return False

        elif len(password) < 8:
            messagebox.showinfo(title="Oops", message="Please make sure that the password's length is at least 8 characters")
            return False

        else:
            is_ok = messagebox.askyesno(title=name, message=f"These are the details entered : \nName: {name}\nWebsite: {website} \nEmail: {email} \nPassword: {password_entry.get()} \nAre you sure you want to save this? " )
            if is_ok == True:
                insert_fields = """INSERT INTO vault(website, name, username, password, notes)
            VALUES(?, ?, ?, ?, ?) """
                cursor.execute(insert_fields, (website, name, email, password, notes))
                db.commit()
                vaultScreen(window_var)
                return True

            else:
                messagebox.showinfo("Your password was not saved", "Your password was not saved")
                return False

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

# ------------------------------------------------------------------------------------ UPDATE APP ----------------------------------------------------------------------------- #
def update():
    try:
        currentversion = get_request("https://raw.githubusercontent.com/Mitra-Electronics/passwordmanagerbyishanverstionupdate.tct.txt/main/version.txt").text
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Internet was accessed by app to check for updates" + "\n")
            log_file.close()

        if float(__version__) < float(currentversion):
            ask_update = messagebox.askyesno(title="Software Update", message="Update available for Password Manager by Ishan.\nWould you like to update to the latest version?")
            if ask_update == True:
                UpdateManager(window_var)
        elif float(__version__) > float(currentversion) or float(__version__) == float(currentversion):
            messagebox.showinfo(title="Software Update", message="You are on the latest version of Password Manager by Ishan")
        else:
            messagebox.showerror(title="An error occured", message="An error occured")
    
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="No internet connection", message="No internet connection. Could not check for updates")

class UpdateManager(Toplevel):
    def __init__(self, parent):
        try:
            Toplevel.__init__(self, parent)
            self.transient(parent)
            self.result = None
            self.grab_set()
            w = 350
            h = 200
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            x = (sw - w) / 2
            y = (sh - h) / 2
            self.geometry('{0}x{1}+{2}+{3}'.format(w, h, int(x), int(y)))
            self.resizable(width=False, height=False)
            self.title('Update Manager')
            self.wm_iconbitmap('logo.ico')

            image = Image.open('logo.png')
            photo = ImageTk.PhotoImage(image)
            label = Label(self, image=photo)
            label.image = photo
            label.pack()
        
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured while downloading update", message="An error occured. Please see the log file for more details")

        def install_update():
            try:
                ShellExecute(0, 'open', 'Password Manager by Ishan Installer.exe', None, None, 10)
                parent.destroy()
            except Exception as E:
                with open('logs.log', 'a') as log_file:
                    log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                    log_file.close()
                    messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")


        def start_update_manager():
            try:
                with get_request("https://github.com/Mitra-Electronics/passwordmanagerbyishanverstionupdate.tct.txt/blob/main/Password%20Manager%20by%20Ishan%20Installer.exe?raw=true"
                                , stream=True) as r:
                    
                    self.progressbar['maximum'] = int(r.headers.get('Content-Length'))
                    r.raise_for_status()

                    with open('logs.log', 'a') as log_file:
                        log_file.write(str(datetime.now()) + " : " + "Internet was accessed to download updates" + "\n")
                        log_file.close()

                    with open('Password Manager by Ishan Installer.exe', 'wb') as f:
                        for chunk in r.iter_content(chunk_size=4096):
                            if chunk:  # filter out keep-alive new chunks
                                f.write(chunk)
                                self.progressbar['value'] += 4096

                self.button1.config(text='Install', state=NORMAL)

                self.progressbar = ttk.Progressbar(self,
                                            orient='horizontal',
                                            length=200,
                                            mode='determinate',
                                            value=0,
                                            maximum=0)
                self.progressbar.place(relx=0.5, rely=0.5, anchor=CENTER)
                self.button1 = ttk.Button(self, text='Please Wait', state=DISABLED, command=install_update)
                self.button1.place(x=-83, relx=1.0, y=-33, rely=1.0)

                self.t1 = Thread(target=start_update_manager)
                self.t1.start()
        
            except Exception as E:
                with open('logs.log', 'a') as log_file:
                    log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                    log_file.close()
                    messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

# ------------------------------------------------------------------------------------- UI SETUP ------------------------------------------------------------------------------- #
def mainfunc():
    try:
        window=Toplevel()
        global website_entry, email_entry, password_entry, name_entry, notes_entry
        
        for widget in window.winfo_children():
            widget.destroy()

        window.title("Password Manager")
        #window.iconbitmap(BASE_DIR / "logo.ico")
        window.iconbitmap("logo.ico")
        window.geometry('550x450')
        window.config(padx=50, pady=50)
        window.resizable(0, 0)

        canvas = Canvas(window, height=200, width=200)
        #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
        logo_img = PhotoImage(file="logo.png")
        canvas.create_image(100, 100, image=logo_img)
        canvas.grid(row=0, column=1)

        # labels
        name_label = Label(window, text="Name :")
        name_label.grid(row=1, column=0)
        website_label = Label(window, text="Website :")
        website_label.grid(row=2, column=0)
        email_label = Label(window, text="Email/Username :")
        email_label.grid(row=3, column=0)
        password_label = Label(window, text="Password :")
        password_label.grid(row=4, column=0)
        notes_label = Label(window, text="Notes :")
        notes_label.grid(row=5, column=0)
        """created_on = Label(window, text="Created on")
        created_on.grid(row=6, column=0)
        expires_on = Label(window, text="Created on")
        expires_on.grid(row=6, column=0)"""

        # Entries
        name_entry = Entry(window, width=53)
        name_entry.grid(row=1, column=1, columnspan=2)
        name_entry.focus()
        website_entry = Entry(window, width=53)
        website_entry.grid(row=2, column=1, columnspan=2)

        def focus_website_entry(*args):
            website_entry.focus()
        name_entry.bind("<Return>", focus_website_entry)
        
        email_entry = Entry(window, width=53)
        email_entry.grid(row=3, column=1, columnspan=2)
        email_entry.insert(0, "username@example.com")
        def focus_email_entry(*args):
            email_entry.focus()

        website_entry.bind("<Return>", focus_email_entry)
        password_entry = Entry(window, width=35)
        password_entry.grid(row=4, column=1)
        password_entry.bind("<Return>", save)

        def focus_password_entry(*args):
            password_entry.focus()

        email_entry.bind("<Return>", focus_password_entry)
        notes_entry = Entry(window, width=53)
        notes_entry.grid(row=5, column=1, columnspan=2)
        notes_entry.bind("<Return>", save)

        # Buttons
        generate_password_ = Button(window, text="Generate Password", width=14, command=partial(generate_password, password_entry))
        generate_password_.grid(row=4, column=2)
        add_button = Button(window, text="Add", width=36, command=save)
        add_button.grid(row=6, column=1, columnspan=2)

        window.mainloop()

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

def vaultScreen(windowx):
    try:
        for widget in windowx.winfo_children():
            widget.destroy()
    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def ask_to_reset_password():
        try:
            confirmation = messagebox.askyesno(title="Are you sure?", message="Are you sure that you want to reset the master password? \nIt will take a while depending on your processor speed and the number of passwords you have entered since we will have to encode your passwords again.")
            if confirmation == True:
                reset_password(window_var)
            else:
                pass

        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def removeEntry(input: int):
        try:
            ask_delete = messagebox.askyesno("Delete Entry", "Do you really want to delete the password?")
            if ask_delete == True:
                cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
                db.commit()
                vaultScreen(window_var)
                messagebox.showinfo(title="Password Deleted Sucessfully", message="Password Deleted Sucessfully")
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def copyf(input: int):
        try:
            cursor.execute('SELECT password FROM vault WHERE ID = ?', (input,))
            array = cursor.fetchone()
            copy(decrypt_text(array[0]))
            notification.notify(
 			    title = "Password copied to clipboard",
 			    message ="Password copied to clipboard!",
                app_name="Password Generator in Python",
 			    app_icon = "logo.ico",
 			    timeout= 5,
                toast=True,
 			    )
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def update_password(i):
        try:
            cursor.execute("""UPDATE vault SET
            name = :name,
            website = :website,
            username = :username,
            password = :password,
            notes = :notes
            WHERE
            id = :id""",
            {
            'name' : name_entry_edit.get(),
            'website' : website_entry_edit.get(),
            'username' : email_entry_edit.get(),
            'password' : encrypt_text(bytes(password_entry_edit.get(), 'utf-8')),
            'notes' : encrypt_text(bytes(notes_entry_edit.get(), 'utf-8')),
            'id' : i[0]
            })
            db.commit()
            vaultScreen(window_var)

        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def see_notes(note):
        try:
            messagebox.showinfo(title="Notes",message=decrypt_text(note))
        
        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    def change_entry(input):
        global website_entry_edit, email_entry_edit, password_entry_edit, name_entry_edit, notes_entry_edit
        try:
            cursor.execute('SELECT * FROM vault WHERE ID = ?', (input,))
            array = cursor.fetchall()
            window_ = Toplevel()
            for widget in window_.winfo_children():
                widget.destroy()
            window_.title("Change entry")
            #window.iconbitmap(BASE_DIR / "logo.ico")
            window_.iconbitmap("logo.ico")
            window_.geometry('550x400')
            window_.config(padx=50, pady=50)
            window_.resizable(0, 0)

            canvas = Canvas(window_, height=200, width=200)
            #logo_img = PhotoImage(file=BASE_DIR/"logo.png")
            logo_img = PhotoImage(file="logo.png")
            canvas.create_image(100, 100, image=logo_img)
            canvas.grid(row=0, column=1)

            # labels
            name_label = Label(window_, text="Name :")
            name_label.grid(row=1, column=0)

            website_label = Label(window_, text="Website :")
            website_label.grid(row=2, column=0)

            email_label = Label(window_, text="Email/Username :")
            email_label.grid(row=3, column=0)

            password_label = Label(window_, text="Password :")
            password_label.grid(row=4, column=0)

            notes_label = Label(window_, text="Notes :")
            notes_label.grid(row=5, column=0)

            # Entries
            name_entry_edit = Entry(window_, width=53)
            name_entry_edit.grid(row=1, column=1, columnspan=2)
            name_entry_edit.insert(0, (array[0][1]))

            website_entry_edit = Entry(window_, width=53)
            website_entry_edit.grid(row=2, column=1, columnspan=2)
            website_entry_edit.insert(0, (array[0][2]))
            website_entry_edit.focus()

            email_entry_edit = Entry(window_, width=53)
            email_entry_edit.grid(row=3, column=1, columnspan=2)
            email_entry_edit.insert(0, (array[0][3]))

            password_entry_edit = Entry(window_, width=35)
            password_entry_edit.grid(row=4, column=1)
            password_entry_edit.insert(0, decrypt_text(array[0][4]))

            notes_entry_edit = Entry(window_, width=35)
            notes_entry_edit.grid(row=5, column=1)
            notes_entry_edit.insert(0, decrypt_text(array[0][5]))

            # Buttons
            generate_passwordG = Button(window_, text="Generate Password", width=14, command=partial(generate_password, password_entry_edit))
            generate_passwordG.grid(row=4, column=2)
            add_button = Button(window_, text="Update", width=36, command=partial(update_password, array[0]))
            add_button.grid(row=6, column=1, columnspan=2)

            window_var.mainloop()

        except Exception as E:
            with open('logs.log', 'a') as log_file:
                log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                log_file.close()
                messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

    try:
        windowx.title("Password Manager by Ishan")
        menu = Menu(windowx, tearoff=0)
        file_tab = Menu(menu, tearoff=0)
        windowx.config(menu=menu)
        menu.add_command(label="Add Password", command=mainfunc)
        menu.add_cascade(label="Import/Export", menu=file_tab)
        file_tab.add_command(label="Export", command=export_csv)
        file_tab.add_command(label="Import", command=import_csv)
        about_menu = Menu(menu, tearoff=0)
        menu.add_cascade(label="About", menu=about_menu)
        about_menu.add_command(label="Check for updates", command=update)
        about_menu.add_command(label="Reset master password", command=ask_to_reset_password)
        
        frame_canvas = Frame(windowx)
        frame_canvas.pack(fill=BOTH, expand=1)
        frame_canvas.rowconfigure(0,weight=1)
        frame_canvas.columnconfigure(0,weight=1)

        canvas = Canvas(frame_canvas)
        canvas.pack(side=LEFT,fill=BOTH, expand=1)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        hsb = ttk.Scrollbar(frame_canvas, orient=HORIZONTAL, command=canvas.xview)
        hsb.pack(side=BOTTOM, fill=BOTH)
        canvas.configure(xscrollcommand=hsb.set)
        
        vsb = ttk.Scrollbar(frame_canvas, orient=VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        
        vsb = ttk.Scrollbar(frame_canvas, orient=VERTICAL, command=canvas.yview)
        vsb.pack(side=RIGHT, fill=Y)
        vsb.state()
        canvas.configure(yscrollcommand=vsb.set)
        
        # Create a frame to contain the buttons
        window = Frame(canvas)
        canvas.create_window((0, 0), window=window, anchor='nw')
        window.bind_all("<MouseWheel>", _on_mousewheel)
        window.bind("<Configure>", lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        window.bind("<Configure>", lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        window.bind("<Configure>", lambda e:canvas.configure(scrollregion=canvas.bbox("all")))

        windowx.geometry('1200x600')
        windowx.config(padx=5, pady=5)
        windowx.resizable(height=0, width=200)
        lbl = Label(window, text="""Password Manager by Ishan
                    """, font=("Helvetica", 15))
        lbl.grid(row=0,column=2)
        lbl.anchor(CENTER)

        search_button = Button(window, text="Search by username", command=search)
        search_button.grid(row=1, column=2)

        lbl = Label(window, text="Sl. no.")
        lbl.grid(row=2, column=0, padx=20)

        lbl = Label(window, text="Name")
        lbl.grid(row=2, column=1, padx=80)

        lbl = Label(window, text="Website")
        lbl.grid(row=2, column=2, padx=80)

        lbl = Label(window, text="Email or Username")
        lbl.grid(row=2, column=3, padx=80)

        lbl = Label(window, text="Password")
        lbl.grid(row=2, column=4, padx=80)

        cursor.execute('SELECT * FROM vault')
        if (cursor.fetchall() != None):
            try:
                cursor.execute('SELECT * FROM vault')
                array = cursor.fetchall()
                i = 0
                for ayy in array:
                    lbl0 = Label(window, text=(ayy[1]), font=("Helvetica", 12))
                    lbl0.grid(column=1, row=(i+3))

                    lbl00 = Label(window, text=(i+1), font=("Helvetica", 12))
                    lbl00.grid(column=0, row=(i+3))

                    lbl1 = Label(window, text=(ayy[2]), font=("Helvetica", 12))
                    lbl1.grid(column=2, row=(i+3))

                    lbl2 = Label(window, text=(ayy[3]), font=("Helvetica", 12),)
                    lbl2.grid(column=3, row=(i+3))

                    lbl3 = Label(window, text=(decrypt_text(ayy[4])), font=("Helvetica", 12))
                    lbl3.grid(column=4, row=(i+3))

                    copy_btn = Button(window, text="Copy", command=partial(copyf, ayy[0]))
                    copy_btn.grid(column=6, row=(i+3), pady=10)

                    btn = Button(window, text="Delete", command=partial(removeEntry, ayy[0]))
                    btn.grid(column=5, row=(i+3), pady=10)

                    btn_c = Button(window, text="Edit", command=partial(change_entry, ayy[0]))
                    btn_c.grid(column=7, row=(i+3), pady=10)

                    btn_n = Button(window, text="See notes", command=partial(see_notes, ayy[5]))
                    btn_n.grid(column=8, row=(i+3), pady=10)

                    i = i +1

                    cursor.execute('SELECT * FROM vault')
                    if (len(cursor.fetchall()) <= i):
                        break
                    window.update()

            except Exception as E:
                with open('logs.log', 'a') as log_file:
                    if str(E) == 'list index out of range':
                        pass
                    else:
                        log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
                        log_file.close()

    except Exception as E:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")

if __name__ == '__main__':
    try:
        connect()
        window_var = Tk()
        window_var.protocol("WM_DELETE_WINDOW", on_closing)
        cursor.execute('SELECT * FROM masterpassword')
        if (cursor.fetchall()):
            login(window_var)
        else:
            firstTimeScreen(window_var)
    except Exception as E1:
        with open('logs.log', 'a') as log_file:
            log_file.write(str(datetime.now()) + " : " + "Error: " + (str(E1)) + "\n")
            log_file.close()
            messagebox.showerror(title="An error occured", message="An error occured. Please see the log file for more details")
