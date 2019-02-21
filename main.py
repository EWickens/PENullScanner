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
    args = parse_arguments()  # Parses args for arguments

    pe = pefile.PE(args.filename)  # Takes the filename from command line argument and loads PE file

    num_sections = pe.FILE_HEADER.NumberOfSections

    print("Number of Sections: " + str(num_sections))

    last_section = pe.sections[num_sections - 1]  # gets the last section
    print("Writeable: " + str(check_writeable(last_section)))
    print("Executable: " + str(check_executable(last_section)))

    if (check_writeable(last_section) and check_executable(
            last_section)):  # Checks to see if last section is writeable and executable
        hex = binascii.hexlify(last_section.get_data())
        print(hex)
        split_hex = list(hex)
        # print(split_hex)
        print(len(split_hex))

        contiguous_count = 0
        highest_occurrences = 0

        dump = last_section.dump()
        print(dump)

        for val in split_hex:
            if val == '0':
                contiguous_count += 1

                if contiguous_count > highest_occurrences:
                    highest_occurrences = contiguous_count

            else:
                contiguous_count = 0

        print("Highest Occurence: " + str(highest_occurrences))
        if highest_occurrences > 300:
            print("Lot of zero's there boss")

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
    parser.add_argument("-b", "--buffer", dest="buffer",
                        help="Specifies how many 0's to look for default is ",
                        metavar="BUFFER")  # TODO - DETERMINE DEFAULT NUMBER OF ZEROS & SET DEFAULT NUMBER
    # TODO ADD HELP TEXT
    args = parser.parse_args()

    return args


main()
