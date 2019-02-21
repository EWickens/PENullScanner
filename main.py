import argparse
import os
import sys
import scandir
import pefile
import ArgumentParser

# code for scanning files in directory
# if os.path.isdir(args.file):
#         for root, dirs, files in scandir.walk(args.file):
#             for file in files:

def main():
    args = parse_arguments() # Parses args for arguments

    pe = pefile.PE(args.filename) # Takes the filename from command line argument and loads PE file

    num_sections = pe.FILE_HEADER.NumberOfSections

    print("Number of Sections: " + str(num_sections))

    last_section = pe.sections[num_sections-1] # gets the last section
    print("Writeable: " + str(check_writeable(last_section)))
    print("Executable: " + str(check_executable(last_section)))

    if(check_writeable(last_section) and check_executable(last_section)): #Checks to see if last section is writeable and executable
        print(last_section)
    else:
        exit()

def check_executable(last_section):
    characteristics = getattr(last_section, 'Characteristics')
    if characteristics & 0x00000020 > 0 or characteristics & 0x20000000 > 0:
        return True

    return False

def check_writeable(last_section):
    characteristics = getattr(last_section, 'Characteristics')
    if characteristics & 0x00000020 > 0 or characteristics & 0x80000000L > 0:
        return True

    return False

def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument("-f", "--file", dest="filename",
                        help="Specify file to be scanned", metavar="FILE")

    args = parser.parse_args()

    return args
main()