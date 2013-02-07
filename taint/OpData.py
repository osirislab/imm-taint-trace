from Operation import *
from Operand import *
from Constants import *
from funct import *

from immlib import *
from libanalyze import *

imm = Debugger()

class OpData:
	def __init__(self, regs, opc):
		self.opcode    = opc
		self.operations= []
		self.operands  = []
		self.valid     = False

		opc_cmdname = opc.getDisasm().split(' ')[0].lower()
		opc_cmdtype = opc.getCmdType()


		#Populate operands
		for i in range(0, 3):
			oprnd = None
			opc_oprnd = opc.operand[i]
			otype = opc_oprnd[0]
			osize = opc_oprnd[1]

			if  (otype & DECR_ISREG):
				self.operands.append(Operand(OPRND_REG, osize, [IMMREG_MAP[osize][opc_oprnd[2].index(1)]]))

			elif(otype & DEC_CONST):
				self.operands.append(Operand(OPRND_CONST, osize, [opc_oprnd[3]]))

			#Special case for lea
			elif(otype == DEC_UNKNOWN and osize == 4):
				for i in range(len(opc_oprnd[2])):
					if(not opc_oprnd[2][i]): continue
					self.operands.append(Operand(OPRND_REG, osize, [IMMREG_MAP[osize][i]]))

			elif(otype & DEC_TYPEMASK):
				self.operands.append(Operand(OPRND_MEM, osize, [IMMREG_MAP[osize][i] for i in len(opc_oprnd[2]) if opc_oprnd[2][i]], calcaddr(opc_oprnd, regs)))


		#Figure out what type of operation it is and parse accordingly
		if  (opc_cmdtype == C_CMD):
			if  (opc_cmdname in ['adc','add','sub','sbb','and','or','xor','shld','shrd']):
				self.operations.append(Operation(OPRTN_ARITH, [self.operands[0], self.operands[1]], [self.operands[0]]))

			elif(opc_cmdname in ['inc','dec','not','neg','shl','shr','sal','sar','shr','rcl','rcr','rol','ror']):
				self.operations.append(Operation(OPRTN_ARITH, [self.operands[0]], [self.operands[0]]))

			elif(opc_cmdname in ['mov','movsx','movzx']):
				self.operations.append(Operation(OPRTN_OVERWRITE, [self.operands[1]], [self.operands[0]]))

			elif(opc_cmdname in ['lea']):
				self.operations.append(Operation(OPRTN_ARITH, self.operands[1:], [self.operands[0]]))

			elif(opc_cmdname in ['div','idiv','mul','imul','imul','imul']):
				ocount = len(self.operands)
				if  (ocount == 1):
					oxsize = self.operands[0].size
					dest = []
					if  (oxsize == 1):
						dest.append(Operand(OPRND_REG, 2, [REG_MAP['AX']]))
					elif(oxsize == 2):
						dest += [Operand(OPRND_REG, 2, [REG_MAP['DX']]), Operand(OPRND_REG, 2, [REG_MAP['AX']])]
					elif(oxsize == 4):
						dest += [Operand(OPRND_REG, 4, [REG_MAP['EDX']]), Operand(OPRND_REG, 4, [REG_MAP['EAX']])]
					self.operations.append(Operation(OPRTN_ARITH, [self.operands[0], Operand(OPRND_REG, oxsize, [IMMREG_MAP[oxsize][0]])], dest))
				elif(ocount == 2):
					self.operations.append(Operation(OPRTN_ARITH, [self.operands[0], self.operands[1]], [self.operands[0]]))
				elif(ocount == 3):
					self.operations.append(Operation(OPRTN_ARITH, [self.operands[1], self.operands[2]], [self.operands[0]]))

 			elif(opc_cmdname in ['cbw','cwd']):
				self.operations.append(Operation(OPRTN_ARITH, [Operand(OPRND_REG, 1, [REG_MAP['AL']])], [Operand(OPRND_REG, 2, [REG_MAP['DX']]), Operand(OPRND_REG, 2, [REG_MAP['AX']])]))

			elif(opc_cmdname in ['cwde','cdq']):
				dest = [Operand(OPRND_REG, 4, [REG_MAP['EAX']])]
				if(opc_cmdname == 'cdq'): dest.append(Operand(OPRND_REG, 4, [REG_MAP['EDX']]))
				self.operations.append(Operation(OPRTN_ARITH, [Operand(OPRND_REG, 2, [REG_MAP['AX']])], dest))

			elif(opc_cmdname in ['smsw']):
				self.operations.append(Operation(OPRTN_OVERWRITE, [Operand(OPRND_CLEAN, 2)], [self.operands[0]]))

			elif(opc_cmdname in ['xchg','xadd']):
				self.operations.append(Operation(OPRTN_OVERWRITE, [self.operands[0]], [self.operands[1]]))
				type = OPRTN_OVERWRITE
				src = [self.operands[1]]
				if(opc_cmdname == 'xadd'):
					type = OPRTN_ARITH
					src.append(self.operands[0])
				self.operations.append(Operation(type, src, [self.operands[0]]))

			elif(opc_cmdname in ['cmp', 'test', 'nop']):
				pass

			else:
				imm.log('Not implemented!' + opc_cmdname)
				return

		elif(opc_cmdtype == C_PSH):
			self.operations.append(Operation(OPRTN_OVERWRITE, [self.operands[0]], [Operand(OPRND_MEM, 4, [REG_MAP['ESP']], regs['ESP'] - 4)]))

		elif(opc_cmdtype == C_POP):
			self.operations.append(Operation(OPRTN_OVERWRITE, [Operand(OPRND_MEM, 4, [REG_MAP['ESP']], regs['ESP'])], [self.operands[0]]))

		elif(opc_cmdtype == C_MMX):
			imm.log('Not implemented!' + opc_cmdname)
			return

		elif(opc_cmdtype == C_FLT):
			imm.log('Not implemented!' + opc_cmdname)
			return

		elif(opc_cmdtype == C_JMP):
			#Don't care about this instruction type
			pass

		elif(opc_cmdtype == C_JMC):
			#Don't care about this instruction type
			pass

		elif(opc_cmdtype == C_CAL):
			#Don't care about this instruction type
			pass

		elif(opc_cmdtype == C_RET):
			#Don't care about this instruction type
			pass

		elif(opc_cmdtype == C_FLG):
			imm.log('Not implemented!' + opc_cmdname)
			return

		elif(opc_cmdtype == C_RTF):
			imm.log('Not implemented!' + opc_cmdname)
			return

		elif(opc_cmdtype == C_REP):
			imm.log('Not implemented!' + opc_cmdname)
			return

		elif(opc_cmdtype == C_PRI):
			imm.log('Not implemented!' + opc_cmdname)
			return

		elif(opc_cmdtype == C_SSE):
			imm.log('Not implemented!' + opc_cmdname)
			return

		elif(opc_cmdtype == C_NOW):
			imm.log('Not implemented!' + opc_cmdname)
			return

		elif(opc_cmdtype == C_BAD):
			imm.log('Bad op encountered')
			return

		else:
			imm.log('Unknown op encountered')
			return


		#If we're here, the opcode is valid
		self.valid = True