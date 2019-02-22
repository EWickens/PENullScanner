import argparse
import os
import sys
import scandir
import pefile
import ArgumentParser
import binascii


# code for scanning files in directory
# if os.path.isdir(args.file):
#         for root, dirs, files in scandir.walk(args.file):
#             for file in files:

def main():
    DEFAULT_BUFFER_SIZE = 800

    args = parse_arguments()  # Parses args for arguments

    file = args.filename

    if args.buffer > 0:
        buffer_size = args.buffer
    else:
        buffer_size = DEFAULT_BUFFER_SIZE

    pe = pefile.PE(file)  # Takes the filename from command line argument and loads PE file
    num_sections = pe.FILE_HEADER.NumberOfSections

    verbose = False

    if args.verbose:
        verbose = True

    last_section = pe.sections[num_sections - 1]  # gets the last section
    result = check_for_null(file, last_section, verbose, buffer_size)

    print("Result: " + str(result))


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
    parser = argparse.ArgumentParser(
        description="Parse a file for a RWX last section and determine if it contains a section of NULL bytes of a specified size")

    parser.add_argument("-f", "--file", dest="filename",
                        help="Specify file to be scanned", metavar="<file>", required=True)
    parser.add_argument("-b", "--buffer", dest="buffer",
                        help="Specifies how many 0's to look for default is - Default is 800 bytes",
                        metavar="<buffSize>")
    parser.add_argument("-v", "--verbose",
                        help="Displays information regarding the PE File", action='store_true')

    args = parser.parse_args()


    return args


def read_from_hex_offset(file, hex_offset, size):
    file = open(file)

    offset = int(hex_offset, base=16)
    file.seek(offset, 0)

    data = file.read(size)
    with open("out.bin", 'wb') as outfile:
        outfile.write(data)

    return data


def check_for_null(file, last_section, verbose, buffer_size):
    writeable = check_writeable(last_section)
    executable = check_writeable(last_section)

    if verbose:
        print(last_section)
        print("Writeable: " + str(writeable))
        print("Executable: " + str(executable))

    if writeable and executable:  # Checks to see if last section is writeable and executable

        '''If the section size is in effective Twos Compliment (i.e. 0xFFFFXXXX) then adjust size accordingly'''
        if "0xf" in hex(last_section.SizeOfRawData):
            size = 0xFFFFFFFF - last_section.SizeOfRawData
        else:
            size = last_section.SizeOfRawData

        # Reads from the hex offset
        split_hex = read_from_hex_offset(file, hex(last_section.PointerToRawData), size)

        # Converts into a list
        split_hex = list(split_hex)

        # print(split_hex)
        contiguous_count = 0
        highest_occurrences = 0

        for val in split_hex:
            if val == '\x00':
                contiguous_count += 1

                if contiguous_count > highest_occurrences:
                    highest_occurrences = contiguous_count

            else:
                contiguous_count = 0

        print("Highest Occurence: " + str(highest_occurrences))
        if highest_occurrences > buffer_size:
            return True

    else:
        return False


main()
