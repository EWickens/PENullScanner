import argparse
import csv
import os
import sys
import pefile


def main():
    buffer_size = 800

    args = parse_arguments()  # Parses args for arguments

    if args.buffer > 0:
        buffer_size = int(args.buffer)

    buffer_size = buffer_size / 2  # This is done due to hex being parsed in pairs of 00's.

    print("\n=================================================================")
    print("Processing files, if specified, results will be in the output CSV")
    print("     Default buffer size is 800 bytes null bytes, -b to modify")
    print("=================================================================\n")

    if args.filename is not None:
        file = args.filename
        file_handler(file, args, buffer_size)

    else:
        CSV_handler(args, buffer_size)


def file_handler(file, args, buffer_size):
    pe = pefile.PE(file)  # Takes the filename from command line argument and loads PE file
    num_sections = pe.FILE_HEADER.NumberOfSections

    last_section = pe.sections[num_sections - 1]  # gets the last section

    if last_section.SizeOfRawData == 0:
        return False, "Empty"
    else:
        result = check_for_null(file, last_section, args.verbose, buffer_size)

        if args.dir is not None:
            print("Result: " + str(result))
        return result, None


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
                        help="Specify file to be scanned", metavar="<file>")
    parser.add_argument("-b", "--buffer", dest="buffer",
                        help="Specifies how many 0's to look for default is - Default is 800 bytes",
                        metavar="<buffSize>")
    parser.add_argument("-v", "--verbose",
                        help="Displays information regarding the PE File", action='store_true')
    parser.add_argument("-d", "--dir", metavar="<dir>",
                        help="Specify directory of files to scan")
    parser.add_argument("-i", "--inputcsv", metavar="<path>",
                        help="Specifies input CSV ")
    parser.add_argument("-o", "--outputcsv", metavar="<path>",
                        help="Specifies output CSV ")

    args = parser.parse_args()

    return args


def read_from_hex_offset(file, hex_offset, size):
    file = open(file)

    offset = int(hex_offset, base=16)
    print(hex_offset)
    file.seek(offset, 0)

    data = file.read(size)

    return data


def check_for_null(file, last_section, verbose, buffer_size):
    writeable = check_writeable(last_section)
    executable = check_executable(last_section)

    split = file.split('/', 1)[-1]
    print("\n\nFileID: " + split)

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

        if verbose:
            print("Highest Occurrence: " + str(highest_occurrences))

        if highest_occurrences >= buffer_size:
            return True
        else:
            return False
    else:
        return False


def CSV_handler(args, buffer_size):  # Adapted from TJ's code from yara classifier

    global fieldnames
    if not os.path.exists(args.inputcsv):
        print("[-] ERROR: Input CSV file does not exist! ")
        exit(2)
    if not os.path.exists(args.dir):
        print("[-] ERROR: Files directory does not exist! ")
        exit(2)

    with open(args.inputcsv) as csvfile:
        reader = csv.DictReader(csvfile)

        if "Gaps In RWX" in reader.fieldnames:
            fieldnames = reader.fieldnames
        else:
            fieldnames = reader.fieldnames + ['Gaps In RWX']

        # Generate output file, version check to avoid Windows vs MAC output bug
        if sys.version_info[0] == 2:
            fileout = open(args.outputcsv, 'wb')
        else:
            fileout = open(args.outputcsv, 'w')

        writer = csv.DictWriter(fileout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            path = os.path.join(args.dir, row['SHA256'])
            try:
                result = file_handler(path, args, buffer_size)

                if not result[0] and result[1] == "Empty":
                    row['Gaps In RWX'] = "Empty"
                elif result[0] and result[1] is None:
                    row['Gaps In RWX'] = "True"
                elif not result[0] and result[1] is None:

                    row['Gaps In RWX'] = "False"


            except Exception as e:
                print ("Error Scanning: {0}".format(row['SHA256']))
                print ("    {0}").format(e)
            writer.writerow(row)
        fileout.close()
        print "Output written to {}".format(args.outputcsv)


main()
