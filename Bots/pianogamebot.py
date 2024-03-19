from pyautogui import *
import pyautogui
import time
import keyboard
import random
import win32api, win32con

# Change pixels  

def click(x,y):
    win32api.SetCursorPos((x,y))
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN,0,0)
    time.sleep(0.01)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP,0,0)

while keyboard.is_pressed('q') == False:

    if pyautogui.pixel (1456, 604)[0] == 0:
        click(1456, 604)
    if pyautogui.pixel (1530, 600)[0] == 0:
        click(1530, 600)
    if pyautogui.pixel (1659, 603)[0] == 0:
        click(1659, 603)
    if pyautogui.pixel (1768, 603)[0] == 0:
        click(1768, 603)
