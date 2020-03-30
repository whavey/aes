'''
Wayne Havey
UCCS - CS5920 - HW #3
March 2020
AES Encryption Class that encrypts and self.output_lines.appends state values along the way.
'''

import numpy as np
import sys
import binascii

class Aes:
# Main class that encrypts and stores output lines

    def __init__(self, rounds = 10):
    # Initialize object with global properties

        self.output_lines = [] # for print state during transistions
        self.just_state_lines = [] # for storing just the state
        self.state = None # maintain state while processing rounds
        self.rounds = rounds # number of rounds to run. Only 10 in this case.
        self.blocks = [] # keep track of blocks. only 1 in this case.
        self.key = None # hold key
        self.plaintext = None # hold plaintext

        # The values for matrix GF multiplication
        self.mix_matrix = bytearray([
            0x02, 0x03, 0x01, 0x01, 
            0x01, 0x02, 0x03, 0x01, 
            0x01, 0x01, 0x02, 0x03,
            0x03, 0x01, 0x01, 0x02
            ])

        # Hardcoded Rcon arrays for key expansion per round
        self.Rcon = [
            bytearray([0x01, 0x00, 0x00, 0x00]), 
            bytearray([0x02, 0x00, 0x00, 0x00]), 
            bytearray([0x04, 0x00, 0x00, 0x00]), 
            bytearray([0x08, 0x00, 0x00, 0x00]), 
            bytearray([0x10, 0x00, 0x00, 0x00]), 
            bytearray([0x20, 0x00, 0x00, 0x00]), 
            bytearray([0x40, 0x00, 0x00, 0x00]), 
            bytearray([0x80, 0x00, 0x00, 0x00]), 
            bytearray([0x1b, 0x00, 0x00, 0x00]), 
            bytearray([0x36, 0x00, 0x00, 0x00])
        ]

        # hardcoded sbox matrix
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16
        ] 

    @property
    def key(self):
    # get key
        return self.__key

    @key.setter
    def key(self, key):
    # set key
        self.__key = key

    @property
    def plaintext(self):
    # get PT
        return self.__plaintext

    @plaintext.setter
    def plaintext(self, plaintext):
    # set PT
        self.__plaintext = plaintext

    def make_blocks(self):
    # Handles separating blocks if > 16 bytes. Only 1 in the case of this homework.

        self.hex_plaintext = bytes.fromhex(self.plaintext)

        num_blocks = int( len(self.hex_plaintext) / 16 )
        block_num = 1 
        first_byte = 0
        last_byte = 16

        while block_num <= num_blocks:
            self.blocks.append(bytearray(self.hex_plaintext[first_byte:last_byte]))
            block_num += 1
            first_byte += 16
            last_byte += 16

        self.output_lines.append(f"BLOCKS to process ({num_blocks}):")
        for b in self.blocks:
            self.output_lines.append(f'\t{binascii.hexlify(b)}')

    def expand_key(self):
    # Handles key expansion. Initializes self.expanded_key property.

        self.hex_key =  bytes.fromhex(self.key)

        # list of keys for each round.
        self.expanded_key = [[],[],[],[],[],[],[],[],[],[],[]]
        key_rows = [] 

        # Start with initial key for initial round
        self.expanded_key[0].append(self.hex_key[0:4])
        key_rows.append(self.hex_key[0:4])
        self.expanded_key[0].append(self.hex_key[4:8])
        key_rows.append(self.hex_key[4:8])
        self.expanded_key[0].append(self.hex_key[8:12])
        key_rows.append(self.hex_key[8:12])
        self.expanded_key[0].append(self.hex_key[12:16])
        key_rows.append(self.hex_key[12:16])

        self.output_lines.append('\nKEY EXPANSION TABLE:') 

        i = 4 # start with for for after initial round
        key_index = 0 
        
        while i < 44: # generate 10 round keys
            temp = key_rows[i-1]

            if i%4 == 0:
                self.output_lines.append(f"{'='*10}\nkey Words:") 
                for j in range(4):
                    self.output_lines.append(f'w{j+i} = {binascii.hexlify(self.expanded_key[key_index][j])}')

                self.output_lines.append("\nAuxiliary Functions:")
                key_index += 1

                rotated = self.left_cir_shift(temp)
                self.output_lines.append(f'RotWord (w{i-1}) = {binascii.hexlify(rotated)} = x{key_index}')

                substituted = self.subword(rotated, 4)
                self.output_lines.append(f'SubWord (x{key_index}) = {binascii.hexlify(substituted)} = y{key_index}')

                rrcon = bytearray(self.Rcon[int(i/4)-1])
                self.output_lines.append(f'Rcon ({key_index}) = {binascii.hexlify(rrcon)}')

                temp = bytearray(substituted  ^ rrcon  for (substituted, rrcon) in zip(substituted, rrcon))
                self.output_lines.append(f'y{key_index} XOR Rcon ({key_index}) = {binascii.hexlify(temp)} = z{key_index}')

            w = key_rows[i-4]
            xor = bytes(w ^ temp for (w, temp) in zip(w, temp))
            self.expanded_key[key_index].append( xor )
            key_rows.append( xor )

            i += 1

        self.output_lines.append(f"\n {'='*10}\nkey Words:") 
        for j in range(4):
            self.output_lines.append(f'w{j+i} = {binascii.hexlify(self.expanded_key[key_index][j])}')

        self.output_lines.append('*'*10)

    def subword(self, word, size):
    # handles byte substitution with sbox. Returns array of bytes representing state after substitution.

        subbed = []
        for i in range(size):
            subbed.append(self.sbox[word[i]])
            
        return bytearray(subbed)

    def left_cir_shift(self, word):
    # shift function for key expansion only.

        lword = list(word)
        return bytearray([lword[1],lword[2],lword[3],lword[0]])

    def round_shift(self, block):
    # handles byte shifting for rounds. Maybe not most efficient but its simple and it works.

        lblock = list(block)
        return bytearray([
            lblock[0], 
            lblock[1], 
            lblock[2],
            lblock[3],
            lblock[5],
            lblock[6],
            lblock[7],
            lblock[4],
            lblock[10],
            lblock[11],
            lblock[8],
            lblock[9],
            lblock[15],
            lblock[12],
            lblock[13],
            lblock[14],
        ])

    def add_round_key(self, block, round, transpose=True):
    # Function to add the round key to state as provided by key expansion function.

        # These stanzas with the map functions handle simulating transposing the byte matrices.
        # Theres a function to do this but Im done working on this...
        trk = list(map(list, zip(*self.expanded_key[round])))
        trk_bytes = bytearray()
        for i in range(4):
            for j in range(4):
                trk_bytes.extend(int.to_bytes(trk[i][j], 1, 'big'))

        tblk_bytes = block
        if transpose:
            blocklist = [block[0:4], block[4:8], block[8:12], block[12:16]]
            tblk = list(map(list, zip(*blocklist)))
            tblk_bytes = bytearray()
            for i in range(4):
                for j in range(4):
                    tblk_bytes.extend(int.to_bytes(tblk[i][j], 1, 'big'))
 
        self.output_lines.append("\nRound key:")
        self.matrixify(trk_bytes)

        # Adding round key is just XOR of state with round key
        self.state = bytearray(tblk_bytes ^ trk_bytes for (tblk_bytes, trk_bytes) in zip(tblk_bytes, trk_bytes)) 

    def gf_add(self, b1, b2, b3, b4): 
    # Gallois Field add function

        return int(bin((int(b1, 2) ^ int(b2, 2) ^ int(b3, 2) ^ int(b4, 2))&0b11111111), 2)
        
    def gf_mul(self, b1, b2): 
    # Gallois Field mutliply function. The commented out output_lines.append lines were for troubleshooting and checking.

        #self.output_lines.append("\n", b1, "->", int.to_bytes(b1, 1, 'big'), "->", bin(b1), '\n', b2, "->", int.to_bytes(b2, 1, 'big'), '->', format(b2, '#010b'))

        starts_1 = True if format(b2, '#010b').startswith("1", 2) else False # checks if byte string starts with bit 1.
        if b1 == 1:
            #self.output_lines.append("b1 is 1 so returning b2.")
            res = bin(b2)

        elif b1 == 2:
            #self.output_lines.append('b1 is 2.')

            # If mix columns matrix element was a 01 and a mod m(x) required.
            if starts_1: 
                #self.output_lines.append('b2 starts with 1.')
                res = bin(((b2 << 1)&0b11111111)^0b00011011)
                #self.output_lines.append( 'shift mod m(x) ->', res )

            # No mod m(x) required
            else:
                res = bin((b2 << 1)&0b11111111)
                #self.output_lines.append('b2 starts with 0. shift no mod ->', res)
            
        # Mix column matrix element was 03
        else:
            #self.output_lines.append('b1 is 3.')

            # Requires mod m(x)
            if starts_1:
                res = bin(((((b2 << 1)&0b11111111)^0b00011011)^b2)&0b11111111)

            else:
                res = bin(((b2 << 1)^b2)&0b11111111)
                #self.output_lines.append("b2-shift mod b2 ->", res)

        return res

    def mix_columns(self, state):
    # Handles mix columns step. Makes use of gf_mul and gf_add functions.

        # Again. For tranposing matrix.
        statelist = [state[0:4], state[4:8], state[8:12],state[12:16]]
        sblk = list(map(list, zip(*statelist)))
        sblk_bytes = bytearray()
        for i in range(4):
            for j in range(4):
                sblk_bytes.extend( int.to_bytes(sblk[i][j], 1, 'big'))

        result = bytearray()

        # Simulate GF matrix multiply by doing gf_mul and then gf_add of those results.
        # The transposing allows for simulating matrix operations.
        i = 0
        while i < 16:
            j = 0
            while j < 16:
                m1 = self.gf_mul(self.mix_matrix[i], sblk_bytes[j])
                m2 = self.gf_mul(self.mix_matrix[i+1], sblk_bytes[j+1])
                m3 = self.gf_mul(self.mix_matrix[i+2], sblk_bytes[j+2])
                m4 = self.gf_mul(self.mix_matrix[i+3], sblk_bytes[j+3])
                a = self.gf_add(m1, m2, m3, m4)
                #self.output_lines.append('extending with:', int.to_bytes(a, 1, 'big'))
                result.extend( int.to_bytes(a, 1, 'big') )
                j += 4 
            i += 4

        return result

    def round(self, round):
    # Handles running a round.

        # Substitute step
        self.state = self.subword(self.state, 16)
        self.output_lines.append("\nAfter SubBytes:") 
        self.matrixify(self.state)

        # shift step
        self.state = self.round_shift(self.state)
        self.output_lines.append("\nAfter ShiftRows:") 
        self.matrixify(self.state)

        # Dont do mix columns if last round
        if round < self.rounds-1:

            # Do mix columns step.
            self.state = self.mix_columns(self.state)
            self.output_lines.append("\nAfter MixColumns:") 
            self.matrixify(self.state)

        # do add round step
        self.add_round_key(self.state, round+1, False)
        self.just_state_lines.append(f'{binascii.hexlify(self.transpose(self.state))}')

    def transpose(self, block):
    # Function for transposing matrix. Should be using this more...
        statelist = [block[0:4], block[4:8], block[8:12], block[12:16]]
        sblk = list(map(list, zip(*statelist)))
        sblk_bytes = bytearray()
        for i in range(4):
            for j in range(4):
                sblk_bytes.extend( int.to_bytes(sblk[i][j], 1, 'big'))

        return sblk_bytes 

    def matrixify(self, block):
    # Just for printing state and byte strings in a matrix like format.

        matrix = [block[0:4], block[4:8], block[8:12], block[12:16]]
        for i in range(4):
            line = "" 
            for j in range(4):
                line += f"{binascii.hexlify(int.to_bytes(matrix[i][j], 1, 'big'))}"
            self.output_lines.append(line)
        
    def process_block(self, block):
    # Process a block. Really not that necessary since only using one block for this homework.

        # start with key expansion
        self.expand_key()

        self.output_lines.append(f'{"="*8}\nStart Of Round initial:') 
        self.matrixify(self.transpose(block))
        self.just_state_lines.append(f'{binascii.hexlify(block)}')

        # Add round key for initial transformation.
        self.add_round_key(block, 0)
        self.just_state_lines.append(f'{binascii.hexlify(self.transpose(self.state))}')

        # Run the rounds for this block
        round = 0
        while round < self.rounds:
            self.output_lines.append(f'{"="*8}\nStart Of Round {round+1}:') 
            self.matrixify(self.state)

            self.round(round)
            round += 1

        self.output_lines.append("\nFinal State:")
        self.matrixify(self.state)

        return self.state # this will be the encrypted final byte array needing to be transposed.

    def encrypt(self):
    # make the blocks if more than 1 and process each.
    # if there were more than 1 I think I would just append the values for each process_block to one string.

        self.make_blocks()
        for block in self.blocks:
            self.process_block(block)

        return self.transpose(self.state) # The final actual encrypted value.

    def decrypt(self):
    # Thank God I didnt have to implement this already spend way to much time on this...
        pass

def bit_diff(p1, p2):
# Function to get bit difference count between two states.
# get the bytes of the state, then the bits from that, then accumulate the differences.

   for i in range(len(p_state_lines)):
       p_bytes = bytes.fromhex(p1[i][2:-1])
       p_bits = [format(x, '08b') for x in p_bytes]

       p2_bytes = bytes.fromhex(p2[i][2:-1])
       p2_bits = [format(x, '08b') for x in p2_bytes]

       bit_diff = 0
       for k in range(len(p_bits)):
           bit_diff += sum( p_bits[k][j] != p2_bits[k][j] for j in range(len(p_bits[k])))

       print(f'\nround: {i}\np: {p_state_lines[i]}\np2: {p2_state_lines[i]}\nNumber of bits that differ: {bit_diff}')

if __name__ == "__main__":
# get object, set plaintext, set key, run encrypt to populate lines to simulate tables from books. Print.

   print("for problem 4:")
   aes_obj = Aes() 
   aes_obj.plaintext = "0123456789abcdeffedcba9876543210"
   aes_obj.key = "0f1571c947d9e8591cb7add6af7f6798"
   encrypted = aes_obj.encrypt()
   for line in aes_obj.output_lines:
       print(line)

   print("\n\nEncrypted:\n", binascii.hexlify(encrypted))

   print("for problem 5:")
   aes_obj1 = Aes()
   aes_obj1.plaintext = "8123456789abcdeffedcba9876543210"
   aes_obj1.key = "0f1571c947d9e8591cb7add6af7f6798"
   encrypted = aes_obj1.encrypt()
   p_state_lines = aes_obj1.just_state_lines # Get base plaintext state per round.

   print('\n', '='*10, "\nComparing:", "8123456789abcdeffedcba9876543210", 'With:', "8123456789abcdeffedcba9876543211")
   aes_obj2 = Aes()
   aes_obj2.plaintext = "8123456790abcdeffedcba9876543211"
   aes_obj2.key = "0f1571c947d9e8591cb7add6af7f6798"
   encrypted = aes_obj2.encrypt()
   p2_state_lines = aes_obj2.just_state_lines # Get state lines for plaintext with 1 bit difference.
   bit_diff(p_state_lines, p2_state_lines) # Compare with base plaintext state per round lines.

   # Doing it two more times. Why???
   print('\n', '='*10, "\nComparing:", "8123456789abcdeffedcba9876543210", 'With:', "8123456789abcdeffedcba9876543212")
   aes_obj3 = Aes()
   aes_obj3.plaintext = "8123456789abcdeffedcba9876543212"
   aes_obj3.key = "0f1571c947d9e8591cb7add6af7f6798"
   encrypted = aes_obj3.encrypt()
   p3_state_lines = aes_obj3.just_state_lines
   bit_diff(p_state_lines, p3_state_lines)

   print('\n', '='*10, "\nComparing:", "8123456789abcdeffedcba9876543210", 'With:', "8123456789abcdeffedcba9876543213")
   aes_obj4 = Aes()
   aes_obj4.plaintext = "8123456789abcdeffedcba9876543213"
   aes_obj4.key = "0f1571c947d9e8591cb7add6af7f6798"
   encrypted = aes_obj4.encrypt()
   p4_state_lines = aes_obj4.just_state_lines
   bit_diff(p_state_lines, p4_state_lines)