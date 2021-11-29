# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import PIL.Image as Image
import numpy
import io
import base64
import cv2
import os
from pathlib import Path

def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    #Read the binary information from the binary file.
    data = Path('C:\\Users\\minhy\\PycharmProjects\\imageGen\\binary.txt').read_bytes()
    print(data)

    arr = []

    for num in range(1200):
        if data[num] == 49:
            arr.append(255)
        else:
            arr.append(0)
        # arr.append(data[num])

    # Make an array of 1,200 random bytes.
    # randomByteArray = bytearray(os.urandom(1200))
    # print(type(os.urandom(1200)))
    flatNumpyArray = numpy.array(arr)

    # Convert the array to make a 400x300 grayscale image.
    grayImage = flatNumpyArray.reshape(30, 40)
    cv2.imwrite('RandomGray.png', grayImage)

    # Convert the array to make a 400x100 color image.
    # bgrImage = flatNumpyArray.reshape(10, 40, 3)
    # cv2.imwrite('RandomColor.png', bgrImage)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
