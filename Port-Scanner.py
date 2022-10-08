# imports
import sys
import socket, threading, time
from tkinter import *
import tkinter
from boto import config
from matplotlib.pyplot import text
import pyfiglet
from datetime import datetime
from colorama import Fore
import re

# === Scan Vars ===
ip_s = ''
ip_f = ''
log = []
ports = []
target = ''


# === Scanning Functions ===
def scan_port(target, port):

    # *************
    try:
        # for port in range(int(ip_s), int(ip_f)):

            ##Port with Large
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((target, port))
            a = 0
            if result == 0:
                a = a+1
                print("Port {} is open".format(port))
            else:
                print("Port {} is closed".format(port))
            s.close()

            ##Port with Small
            # HOST = "erp.vcet.edu.in"
            # PORT = 52
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            b = 0
            if sock.connect_ex((target, port)) == 0:
                b=b+1
                print("Port " + str(port) + " is open didn't connected to anyone")  # Connected successfully
            else:
            # Failed to connect because port is in use (or bad host)
                if  result==0:
                    print("Port " + str(port) + " is open but connected ")
                else:
                    print("Port " + str(port) + " is closed ")

            if a==b==1:

                # l="Port {} is open".format(port)
                # log.append(l)
                # ports.append(port)
                # listbox.insert("end", str(l))
                # update_result()?

                # print("This site is vulnerable to attack!")
                # print('-' * 69)
                # m = ' Port %d \t[open]'%(port,)

                m = "This Port {} is open and vulnerable to attack".format(port)
                log.append(m)
                ports.append(port)
                listbox.insert("end", str(m))
                update_result()
            else:
                # print("Proper site.")
                # print('-' * 69)

                # n = "Port {} is closed\n".format(port)
                # log.append👎
                # ports.append(port)
                # listbox.insert("end", str(n))
                # update_result()

                m = "Port {} is a closed\n".format(port)
                log.append(m)
                ports.append(port)
                listbox.insert("end", str(m))
                update_result()
            

            # Close the connection
            sock.close()

    except OSError:
        print('> Too many open sockets. Port ' + str(port))

    except:
        pass
    sys.exit()

    # except KeyboardInterrupt:
    #     print("\nProgram Exited")
    #     sys.exit()
    # except socket.gaierror:
    #     print("\nThe Host you entered was invalid")
    #     sys.exit()
    # except socket.error:
    #     print("\nServer Error")
    #     sys.exit()
    # *************

    # try:
    #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     s.settimeout(4)
    #     c = s.connect_ex((target, port))
    #     if c == 0:
    #         m = ' Port %d \t[open]'%(port,)
    #         log.append(m)
    #         ports.append(port)
    #         listbox.insert("end", str(m))
    #         update_result()
    #     s.close()

    # except OSError:
    #     print('> Too many open sockets. Port ' + str(port))

    # except:
    #     pass
    # sys.exit()

def start_scan():
    global ports, log, target, ip_f
    clear_scan()
    ports = []

    # Get ports ranges from GUI
    ip_s = int(L24.get())
    ip_f = int(L25.get())

    # Start writing the log file
    log.append('>Port Scanner')
    log.append('=' * 14 + '\n')
    log.append('Target: \t' + str(target))

    try:
        target = socket.gethostbyname(str(L22.get()))
        log.append('IP Adr.:\t' + str(target))
        log.append('Ports \t[' + str(ip_s) + '/' + str(ip_f) + ']')
        log.append('\n')
        # Start Scanning ports.
        while ip_s <= ip_f:
            try:
                scan = threading.Thread(target=scan_port, args=(target, ip_s))
                scan.setDaemon(True)
                scan.start()
            except:
                time.sleep(0.01)
            ip_s += 1
    except:
        m = '>Target' + str(L22.get()) + 'not found.'
        log.append(m)
        listbox.insert(0, str(m))


def save_scan():
    global log, target, ports, ip_f
    log[5] = 'Result:\t[' + str(len(ports)) + '/'+ str(ip_f) + ']\n'
    with open('portscan-' + str(target) + '.txt', mode='wt', encoding='utf-8') as file:
        file.write('\n'.join(log))


def clear_scan():
    listbox.delete(0, 'end')


def update_result():
    rtext = '[' + str(len(ports)) + '/' + str(ip_f) + ']~' + str(target)
    L27.configure(text=rtext)

def clear():
    clear_scan()
    L22.configure(text="0")
    L24.configure(text="0")
    L25.configure(text="0")


































# === GUI ===
gui = Tk()
gui.title('Port Scanner')
gui.geometry('400x600+20+20')

# === Colors ===
m1c = '#141414'
bgc = '#f0e6e6'
dbg = '#cc2929'
fgc = '#f0e6e6'
bcg_img = PhotoImage(file='bcg_photo.png')
icon_img = PhotoImage(file='icon_photo.png')
gui.iconphoto(False, icon_img)

gui.tk_setPalette(background=bgc, foreground=m1c, active_background=fgc, active_foreground=fgc, highlight_color=m1c, highlight_background=m1c)

# === Labels ===
label = Label(gui, image=bcg_img)
label.place(x=0, y=0)

L11 = Label(gui, text='Port Scanner', fg='green', font=('Helvetica', 16, 'bold'))
L11.place(x=30, y=10)

L21 = Label(gui, text = "Target: ", font=('Helvetica', 12))
L21.place(x=16, y=70)

L22 = Entry(gui, text="localhost", font=('Helvetica', 12))
L22.place(x=180, y=70, width=120)
L22.insert(0, "")

L23 = Label(gui, text='Ports: ', font=('Helvetica', 12))
L23.place(x=16, y=110)

L24 = Entry(gui, text='1', font=('Helvetica', 12))
L24.place(x=180, y=110, width = 70)
L24.insert(0, '1')

L25 = Entry(gui, text='1024', font=('Helvetica', 12))
L25.place(x=290, y=110, width=70)
L25.insert(0, '1024')

L26 = Label(gui, text='Result: ', font=('Helvetica', 12))
L26.place(x=16, y=150)

L27 = Label(gui, text='[...]', font=('Helvetica', 12))
L27.place(x=180, y=150)

# === Ports list ===
frame = Frame(gui)
frame.place(x=16, y=190, width=370, height=195)
listbox = Listbox(frame, width=59, height=12)
listbox.place(x=0, y=0)
listbox.bind('<<ListboxSelect>>')
scrollbar = Scrollbar(frame)
scrollbar.pack(side=RIGHT, fill=Y)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview())

# === Buttons/Scans ===
B11 = Button(gui, text='Start Scan', font=('Helvetica', 12), command=start_scan)
B11.place(x=16, y=450, width=170)

B21 = Button(gui, text='Save Result', font=('Helvetica', 12), command=save_scan)
B21.place(x=210, y=450, width=170)

# B31 = Button(gui, text='Clear', font=('Helvetica', 12), command=clear)
# B31.place(x=110, y=520, width=170)

# def delete():
#     L21.delete(3, 'end')

# mybutton = Button(gui, text = "Clear")
# mybutton.pack(x=100, y=450, width=170)


# === Start GUI ===
gui.mainloop()