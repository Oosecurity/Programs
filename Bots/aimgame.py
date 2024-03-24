from pyautogui import *
import pyautogui
import time
import keyboard
import random
import win32api, win32con

time.sleep(2)

#(255,  87,  34)

def click(x,y):
    win32api.SetCursorPos((x,y))
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN,0,0)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP,0,0)
    
while keyboard.is_pressed('q') == False:
    pic = pyautogui.screenshot(region=(540,340,800,490))
    width, height = pic.size

    clicked = False

    for x in range(0,width,5):
        for y in range(0,height,5):
            r,g,b = pic.getpixel((x,y))

            if b == 34 and not clicked:  # Check if a click has already been performed
                click(x+540, y+340)
                time.sleep(0.5)
                clicked = True  # Set the flag to True after clicking
                break

        if clicked:  # If a click has been performed, break out of the outer loop as well
            break

