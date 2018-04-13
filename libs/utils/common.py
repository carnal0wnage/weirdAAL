import os

def list_all_files(directory):
  list_of_files = os.listdir(directory)

  array = []

  for file in list_of_files:
      filename_and_ext = os.path.splitext(file)
      if (filename_and_ext[1] == ".py") and not (filename_and_ext[0].startswith("__")):
          array.append(filename_and_ext[0])
  return array
