import struct
import binascii

def leftrotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def generate_padding(message_byte_length):
    """Generates NIST padding given the current raw message length in bytes."""
    message_bit_length = message_byte_length * 8
    padding = bytearray([0x80])
    while (message_byte_length + len(padding)) % 64 != 56:
        padding.append(0x00)
    padding += struct.pack(b'>Q', message_bit_length)
    return bytes(padding)

def parse_mac(mac_hex):
    """Splits a 40-character hex MAC into h0 to h4."""
    if len(mac_hex) != 40:
        raise ValueError("MAC must be 40 hex characters")
    h = [int(mac_hex[i:i+8], 16) for i in range(0, 40, 8)]
    return h[0], h[1], h[2], h[3], h[4]

class SHA1:
    def __init__(self, h0=None, h1=None, h2=None, h3=None, h4=None, message_byte_length=0):
        self.h0 = h0 if h0 is not None else 0x67452301
        self.h1 = h1 if h1 is not None else 0xEFCDAB89
        self.h2 = h2 if h2 is not None else 0x98BADCFE
        self.h3 = h3 if h3 is not None else 0x10325476
        self.h4 = h4 if h4 is not None else 0xC3D2E1F0
        
        self.message_byte_length = message_byte_length
        self.unprocessed = b''
        self.history = []

    def update(self, data: bytes):
        """Standard update method which accumulates data and processes pure 64-byte blocks."""
        self.unprocessed += data
        self.message_byte_length += len(data)
        
        while len(self.unprocessed) >= 64:
            chunk = self.unprocessed[:64]
            self.unprocessed = self.unprocessed[64:]
            self._process_chunk(chunk)

    def _process_chunk(self, chunk: bytes):
        """Processes precisely 64 bytes of chunk."""
        assert len(chunk) == 64
        w = [0] * 80
        for i in range(16):
            w[i] = struct.unpack(b'>I', chunk[i*4:i*4+4])[0]
            
        for i in range(16, 80):
            val = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]
            w[i] = leftrotate(val, 1)
            
        a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4
        
        block_history = {
            'chunk': chunk.hex(),
            'initial_h': [a, b, c, d, e],
            'rounds': []
        }
        
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
                
            temp = (leftrotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp
            
            block_history['rounds'].append({'a': a, 'b': b, 'c': c, 'd': d, 'e': e})
            
        self.h0 = (self.h0 + a) & 0xFFFFFFFF
        self.h1 = (self.h1 + b) & 0xFFFFFFFF
        self.h2 = (self.h2 + c) & 0xFFFFFFFF
        self.h3 = (self.h3 + d) & 0xFFFFFFFF
        self.h4 = (self.h4 + e) & 0xFFFFFFFF
        
        block_history['final_h'] = [self.h0, self.h1, self.h2, self.h3, self.h4]
        self.history.append(block_history)

    def hexdigest(self):
        """Finalizes the hash and returns the hex digest."""
        padding = generate_padding(self.message_byte_length)
        
        # We manually process remaining unprocessed data + padding
        # so we don't accidentally update `message_byte_length` via `update`
        full_data = self.unprocessed + padding
        for i in range(0, len(full_data), 64):
            self._process_chunk(full_data[i:i+64])
            
        res = '%08x%08x%08x%08x%08x' % (self.h0, self.h1, self.h2, self.h3, self.h4)
        
        self.unprocessed = b''
        return res
