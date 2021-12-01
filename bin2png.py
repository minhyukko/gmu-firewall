# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import PIL.Image as Image
import numpy
import io
import cv2
import sys
import getopt
import math
from pathlib import Path

def bin_to_png(inputfile, outputfile):
    inputfile = Path(inputfile)

    data = inputfile.read_bytes()
    arr = []

    for num in range(len(data)):
        print(len(data))
        if data[num] == 49:
            arr.append(255)
        else:
            arr.append(0)
        # arr.append(data[num])

    # Calculates the minimum length of square to fit all data
    arrayLen = math.sqrt(len(data))
    arrayLen = int(math.ceil(arrayLen))

    for i in range(arrayLen * arrayLen - len(data)): # Pads the remaining space with white space to make the image square
        arr.append(0)

    # Make an array of 1,200 random bytes.
    # randomByteArray = bytearray(os.urandom(1200))
    # print(type(os.urandom(1200)))
    flatNumpyArray = numpy.array(arr)

    # Convert the array to make a 400x300 grayscale image.

    grayImage = flatNumpyArray.reshape(arrayLen, arrayLen)
    cv2.imwrite(outputfile, grayImage)

    # Convert the array to make a 400x100 color image.
    # bgrImage = flatNumpyArray.reshape(10, 40, 3)
    # cv2.imwrite('RandomColor.png', bgrImage)

def main(argv):
    inputfile=''
    outputfile=''
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print("bin2png.py -i inputfile -o outputfile")
        sys.exit(2)
    for opt, arg in opts: #Not sure what your intension was here but I made a quick fix below
        if opt == "-h":
            print("bin2png.py -i <inputfile> -o <outputfile>")
            sys.exit()
        elif opt in ("-i","--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg

    # Quick fix
    inputfile = argv[0]
    outputfile = argv[1]

    bin_to_png(inputfile, outputfile)

if __name__ == '__main__':
    main(sys.argv[1:])
