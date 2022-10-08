import os
import sys
import ctypes


class Amsi:

    AMSI_RESULT = [
        'No malware detected',
        'Malware detected',
        'Amsi initialisation failed',
        'Amsi failed to open session',
        'Amsi string scan failed',
        'Amsi buffer scan failed'
    ]

    dll = ctypes.CDLL("amsiscanner.dll")

    @staticmethod
    def scan_bytes(bytes, name):
        result = Amsi.dll.scanBytes(bytes, len(bytes), name)
        print(Amsi.AMSI_RESULT[result])
        return result

    @staticmethod
    def scan_file(path):
        if not os.path.exists(path):
            raise Exception(f'No such file: {path}')
        file = open(path, 'rb')
        bytes = file.read()
        file.close()
        result = Amsi.dll.scanBytes(bytes, len(bytes), os.path.basename(path))
        print(Amsi.AMSI_RESULT[result])
        return result

    @staticmethod
    def scan_string(text, name):
        result = Amsi.dll.scanString(text, name)
        print(Amsi.AMSI_RESULT[result])
        return result