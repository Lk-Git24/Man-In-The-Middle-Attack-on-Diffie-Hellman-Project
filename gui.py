#gui.py
#!/usr/bin/env python3
import tkinter as Tk
import sys
message_sender_callback = None
input_text_box = None
scrolling_text_box = None
def add_new_text(text):
  scrolling_text_box.insert(Tk.END, text + "\n")
  scrolling_text_box.see(Tk.END)
def send_message_callback():
  if message_sender_callback is None:
      print("Sender callback not registered properly :(")
      sys.exit(1)
  else:
      message = input_text_box.get()
      if message.strip() != '':
          message_sender_callback(message)
          add_new_text("[Me] " + message)
          input_text_box.delete(0, Tk.END)
def set_send_message_callback(callback):
  global message_sender_callback
  message_sender_callback = callback
# تم تعديل الدالة لتقبل مُتغير العنوان 'title' وتعيينه
def start(title="tk", disable_input=False):
  global input_text_box, scrolling_text_box
  top = Tk.Tk()
  top.title(title)  # <--- السطر المُضاف لتعيين العنوان
  scrolling_text_box = Tk.Text(top, height=10)
  scrolling_text_box.pack(fill=Tk.X)
  if not disable_input:
      input_text_box = Tk.Entry(top)
      input_text_box.pack(fill=Tk.X)
      Tk.Button(top, text="Send Message",
                command=send_message_callback).pack()
  top.mainloop()