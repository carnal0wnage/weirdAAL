import os
list_of_files = os.listdir('.')

arry = []

for file in list_of_files:
    filename_and_ext = os.path.splitext(file)
    if filename_and_ext[1] == ".py":
        arry.append(filename_and_ext[0])

__all__ = arry
