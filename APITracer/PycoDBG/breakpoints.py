class Breakpoints:

    addr       = None
    originalByte = None
    handler       = None

    ####################################################################################################################
    def __init__ (self, address, original_byte, handler=None, name=None):

        self.address        = address
        self.original_byte  = original_byte
        self.handler        = handler
        self.name           = name