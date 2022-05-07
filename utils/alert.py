from tkinter import messagebox
import locale


def alert(ip, port=None)->bool:
    localisation = {
        'en': {
            'title': "Warning!",
            'text': f"Suspicious connection!\nFrom IP:{ip}\nBlock it?",
        },
        'ru': {
            'title': "Внимание!",
            'text': f"Подозрительное соединение!\nС IP адреса : {ip}\nЗаблокировать?",
        }
    }
    if 'ru' in locale.getdefaultlocale()[0]:
        loc = 'ru'
    else:
        loc = 'en'
    msg = messagebox.askquestion (localisation[loc]['title'], localisation[loc]['text'],icon = 'warning')
    return True if msg == 'yes' else False

if __name__ == "__main__":
    if alert("192.168.1.15"):
        print("Blocked")
    else:
        print("Skipped")