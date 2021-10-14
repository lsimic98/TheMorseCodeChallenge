#  _     _           _      ___   ___
# | |   (_)         (_)    / _ \ / _ \
# | |___ _ _ __ ___  _  __| (_) | (_) |
# | / __| | '_ ` _ \| |/ __\__, |> _ <
# | \__ \ | | | | | | | (__  / /| (_) |
# |_|___/_|_| |_| |_|_|\___|/_/  \___/

import requests
import jwt

# username = input("Insert username:")
# password = input("Insert password:")

morseCodeHashMap = {
    'a': '.-', 'b': '-...', 'c': '-.-.',
    'd': '-..', 'e': '.', 'f': '..-.',
    'g': '--.', 'h': '....', 'i': '..',
    'j': '.---', 'k': '-.-', 'l': '.-..',
    'm': '--', 'n': '-.', 'o': '---',
    'p': '.--.', 'q': '--.-', 'r': '.-.',
    's': '...',  't': '-', 'u': '..-',
    'v': '...-',  'w': '.--', 'x': '-..-',
    'y': '-.--',  'z': '--..', '1': '.----',
    '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', '0': '-----',
    ',': '--..--', '.':  '.-.-.-', '?': '..--..',
    '/': '-..-.', '-': '-....-', '(': '-.--.', ')': '-.--.-',
    ' ': '/', ':': '---...'
}

def encryptToMorse(plainText):
    cipherText = ''
    for char in plainText:
        cipherText += morseCodeHashMap[char] + ' '
    return cipherText



jwtHeader = {
    'accept': '*/*',
    'Content-Type': 'application/json',
}

jwtData = '{"username":"omega","password":"candidate"}'

jwtResponse = requests.post('http://omega-morse-service.eu-central-1.elasticbeanstalk.com/api/v1/auth', data=jwtData, headers=jwtHeader).json()

print(jwtResponse)

jwtDecodedToken = None

for key, value in jwtResponse.items():
    if key == 'value':
        header_data = jwt.get_unverified_header(value)
        jwtDecodedToken = jwt.decode(
            value,
            key='candidate',
            algorithms=[header_data['alg'], ],
            options={"verify_signature": False}
        )

print(jwtDecodedToken)

concatenated_string = 'Vega IT Omega : ' + str(jwtDecodedToken['exp'])

print(concatenated_string)

cipherText = encryptToMorse(concatenated_string.lower())

print(cipherText)







