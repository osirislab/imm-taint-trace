OPRND_NONE = 0x0
OPRND_REG  = 0x1
OPRND_MEM  = 0x2
OPRND_CONST= 0x3
OPRND_CLEAN= 0x4
OPRND_DIRTY= 0x5

class Operand:
	def __init__(self, type = OPRND_NONE, size = 0, data = [], addr = 0):
		self.type = type
		self.size = size
		self.addr = addr #The resolved address
		self.data = list(data)
			#OPRND_REG:   data = [REG_MAP.XXX]
			#OPRND_MEM:   data = [REG_MAP.XXX, ...], addr = *
			#OPRND_CONST: data = [*]