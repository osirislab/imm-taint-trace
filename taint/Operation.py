OPRTN_NONE     = 0x0
OPRTN_ARITH    = 0x1
OPRTN_OVERWRITE= 0x2

class Operation:
	def __init__(self, type = OPRTN_NONE, src = [], dest = []):
		self.type = type
		self.src  = list(src)
		self.dest = list(dest)