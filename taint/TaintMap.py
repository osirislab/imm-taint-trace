from Constants import *

TMM_BITZERO = 0x01
TMM_BITONE  = 0x02
TMM_BITTWO  = 0x04
TMM_BITTHREE= 0x08
TMM_BITFOUR = 0x10
TMM_BITFIVE = 0x20
TMM_BITSIX  = 0x40
TMM_BITSEVEN= 0x80
TMM_LO      = 0x0F
TMM_HI      = 0xF0
TMM_NONE    = 0x00
TMM_ALL     = 0xFF

TMMDN_BYTE = [TMM_NONE]
TMMDN_WORD = [TMM_NONE,TMM_NONE]
TMMDN_WORDX= [TMM_NONE,TMM_NONE,TMM_NONE]
TMMDN_DWORD= [TMM_NONE,TMM_NONE,TMM_NONE,TMM_NONE]
TMMDN_MAP  = [
	[],         #0
	TMMDN_BYTE, #1
	TMMDN_WORD, #2
	TMMDN_WORDX,#3
	TMMDN_DWORD #4
]

TMMDA_BYTE = [TMM_ALL]
TMMDA_WORD = [TMM_ALL,TMM_ALL]
TMMDA_WORDX= [TMM_ALL,TMM_ALL,TMM_ALL]
TMMDA_DWORD= [TMM_ALL,TMM_ALL,TMM_ALL,TMM_ALL]
TMMDA_MAP  = [
	[],         #0
	TMMDA_BYTE, #1
	TMMDA_WORD, #2
	TMMDA_WORDX, 
	TMMDA_DWORD #4
]

class TaintMap:
	def __init__(self):
		self.map = {}
		self.reg = {}
	
	def setreg(self, regd, mask):
		reg = regd & REGB_REGMASK
		try: self.reg[reg]
		except: self.reg[reg] = list(TMMDN_DWORD)
		c = 4 - 2 * len(mask) if regd & REGB_RHI else 4 - len(mask)
		for i in range(c, 4 - len(mask) if regd & REGB_RHI else 4):
			self.reg[reg][i] = mask[i - c]
	def clearreg(self, regd, mask):
		reg = regd & REGB_REGMASK
		try: self.reg[reg]
		except: self.reg[reg] = list(TMMDN_DWORD)
		c = 4 - 2 * len(mask) if regd & REGB_RHI else 4 - len(mask)
		for i in range(c, 4 - len(mask) if regd & REGB_RHI else 4):
			self.reg[reg][i] &= ~mask[i - c]	
	def getreg(self, regd, mask):
		ret = []
		reg = regd & REGB_REGMASK
		try: self.reg[reg]
		except: self.reg[reg] = list(TMMDN_DWORD)
		c = 4 - 2 * len(mask) if regd & REGB_RHI else 4 - len(mask)
		for i in range(c, 4 - len(mask) if regd & REGB_RHI else 4):
			try: ret.append(self.reg[reg][i] & mask[c])
			except: ret.append(TMM_NONE)
		return ret
	
	def setmem(self, addr, mask):
		for i in range(0, len(mask)):
			self.map[addr + i] = mask[i]
			if(self.map[addr + i] == TMM_NONE): del self.map[addr + i]
	def clearmem(self, addr, mask):
		for i in range(0, len(mask)):
			self.map[addr + i] &= ~mask[i]
			if(self.map[addr + i] == TMM_NONE): del self.map[addr + i]
	def getmem(self, addr, mask):
		ret = []
		for i in range(0, len(mask)):
			try: ret.append(self.map[addr + i] & mask[i])
			except: ret.append(TMM_NONE)
		return ret
	
	def allreg(self):
		return self.reg
	def emptyreg(self):
		self.reg = {}

	def allmem(self):
		return self.map
	def emptymem(self):
		self.map = {}
