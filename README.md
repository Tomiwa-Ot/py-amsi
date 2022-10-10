# py-amsi

py-amsi is a library that scans strings or files for malware using the Windows
Antimalware Scan Interface (AMSI). AMSI is an interface native to Windows 
that allows applications to ask the antivirus installed on the system
to analyse a file/string. AMSI is not tied to Windows Defender. Antivirus
providers implement the AMSI interface to receive calls from applications.
This library takes advantage of the interface to make antivirus scans
in python.

## Installation
- Via pip
  
  ```
  pip install py-amsi
  ```
- Clone repository

  ```bash
  git clone https://github.com/Tomiwa-Ot/py-amsi.git
  cd py-amsi/
  python setup.py install
  ```

## Usage
```python
from pyamsi import amsi

# Scan a file
amsi.scan_file(file_path, debug=True) # debug is optional and False by default

# Scan string
amsi.scan_string(string, string_name, debug=False) # debug is optional and False by default

# Both functions return a dictionary of the format
# {
#     'Sample Size' : 68,         // The string/file size
#     'Risk Level' : 0,           // The risk level as suggested by the antivirus
#     'Message' : 'File is clean' // Response message
# }
```
