<b>Parse a file for a RWX last section and determine if it contains a section of
NULL bytes of a specified size</b>

usage: main.py [-h] [-f <file>] [-b <buffSize>] [-v] [-d <dir>] [-i <path>]
               [-o <path>]

optional arguments:
  -h, --help            show this help message and exit
  -f <file>, --file <file>
                        Specify file to be scanned
  -b <buffSize>, --buffer <buffSize>
                        Specifies how many 0's to look for default is -
                        Default is 800 bytes
  -v, --verbose         Displays information regarding the PE File
  -d <dir>, --dir <dir>
                        Specify directory of files to scan
  -i <path>, --inputcsv <path>
                        Specifies input CSV
  -o <path>, --outputcsv <path>
                        Specifies output CSV


Example command: --dir viri1/ -i Test.csv -o output.csv -b 400