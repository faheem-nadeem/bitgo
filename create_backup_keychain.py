__author__ = 'sameer'

from bitgo import BitGo, Keychains
from sys import argv
from pprint import pprint

if __name__ == "__main__":
    use_production = False

    if len(argv) == 2:
        if argv[1] == 'prod':
            use_production = True


    bitgo = BitGo(use_production=use_production)
    keychain = Keychains(bitgo).create()
    print """
Store the following backup keychain OFFLINE and in a SECURE LOCATION:

"""

    pprint(keychain)

    print """
Submit the following public key to the MultiSig Wallet Initialization form on the Sputnik administration interface:

"""

    print keychain['xpub']

