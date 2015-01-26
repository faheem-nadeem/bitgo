# bitgo
Python BitGo SDK

Note: This requires Pycrypto >= 2.7a1 to encryped/decrypt keys.

    from twisted.internet import reactor
    from twisted.internet.defer import inlineCallbacks
    
    from bitgo import BitGo, BitGoException
    
    @inlineCallbacks
    def main(username, passphrase, otp="0000000"):
        b = BitGo(use_production=False)
        try:
            yield b.authenticate(username, passphrase, otp)
            result = yield b.wallets.list()
            wallets = result["wallets"]
            addresses = wallets.keys()
            if len(addresses) == 0:
                return

            # pick a wallet
            address = addresses[0]
    
            # get the full wallet
            wallet = yield b.wallets.get(address)
    
            # unlock
            yield b.unlock(otp)
    
            # send coins to yourself
            tx = yield wallet.sendCoins(address, wallet.balance / 2, passphrase)
            print tx
        except BitGoException as e:
            print e

    main("foo@bar.com", "super secret")
    reactor.run()

