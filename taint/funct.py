import sys


def calcaddr(oprnd, regs):
	addr = oprnd[3]
	for i in range(len(oprnd[2])):
		addr = (addr + oprnd[2][i] * regs[Registers32BitsOrder[i]]) & 0xffffffff
	return addr

#Debugging stuff
def ByteToHex(byteStr):
    return ''.join( [ "%02X" % ord( x ) for x in byteStr ] ).strip()

def readstr(imm, addr):
	chunk=16
	offset=0
	ret=""
	while(1):
		len=chunk
		buf=imm.readMemory(addr+chunk*offset, chunk)
		offset+=1
		for i in range(0, chunk):
			if(ord(buf[i])==0): 
				len=i
				break
		ret+=buf[0:len]
		if(len<chunk): break
	return ret

def signed(i):
	return -0x100000000+i if i&0x80000000 else i
