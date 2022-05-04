import os
import sys
import time

def main(argv):
    fw_script = './fw_dummy.py'
    ae_script = './ae.py'
    ne_script = './ne.py'
    exit_status = -1

    
    exit_status = os.system('sudo python3 {}'.format(fw_script))
    if(exit_status!=0):
        #redo
    os.system('python3 {}'.fomrat(ae_script))
    if(exit_statu):



if __name__ == '__main__':
    main(sys.argv[1:])
