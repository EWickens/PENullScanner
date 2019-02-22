<b>Parse a file for a RWX last section and determine if it contains a section of
NULL bytes of a specified size</b>

<line>usage: main.py [-h] [-f &ltfile&gt] [-b &ltbuffSize&gt] [-v] [-d &ltdir&gt] [-i &ltpath&gt][-o &ltpath&gt]</line>

optional arguments:
  -h, --help            show this help message and exit
  -f &ltfile&gt, --file &ltfile&gt
                        Specify file to be scanned
  -b &ltbuffSize&gt, --buffer &ltbuffSize&gt
                        Specifies how many 0's to look for default is -
                        Default is 800 bytes
  -v, --verbose         Displays information regarding the PE File
  -d &ltdir&gt, --dir &ltdir&gt
                        Specify directory of files to scan
  -i &ltpath&gt, --inputcsv &ltpath&gt
                        Specifies input CSV
  -o &ltpath&gt, --outputcsv &ltpath&gt
                        Specifies output CSV


Example command: <i>--dir viri1/ -i Test.csv -o output.csv -b 400</i>
