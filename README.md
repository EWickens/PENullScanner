<b>Parse a file for a RWX last section and determine if it contains a section of
NULL bytes of a specified size</b>

This tool is ideally suited to determining if files have been virally infected and since cleaned with an AV leaving code caves (Null sections in the data of a program) which are generally called malware remnants but in our instance we classify it as malware virus unless doing a deep dive on said file.

```usage: main.py [-h] [-f <file>] [-b <buffSize>] [-v] [-d <dir>] [-i <path>][-o <path>]

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

```
<b>Example command:</b> <i>python main.py --dir viri1/ -i Test.csv -o output.csv -b 400</i>

<b>For optimal usage with distro:</b>
  - This tool performs its own check to detect if the last section of a file is Writeable and Executable, so it is not           completely necessary to filter out blanks in the distro.
  - Filter out all packers from cog yara/any sections that are noticeably packed/imphash tags for packing etc..
  - Filter "Gaps in RWX" Section by TRUE
  - Better suited to large groupings on hosts where the host is known to be virally infected (For efficacy purposes)
  
<b>False positives on:</b>
  - Armadillo v1.7.1 -> <i>I have a yara rule for this just ask</i>
  - HASP HL Protection V1.x -> Aladdin - <i>I have a yara rule for this just ask</i>
  - Armadillo V4.x
  - Some ASPack variants
  - PEPack
  - Some Winzip archives
