__VERSION__ = '0.2'
DESC = "None"

import re
import sys

from Constants import * 
from OpData import *
from TaintMap import *
from funct import *

from immlib import *
from libanalyze import *

#Issues
#	-Does not account for flags (SETZ?)
#	-At the moment the table is only used to id stuff...
#	-Gen a graph of data flow
#	-No FPU instructions are supported, no FPU Regs either, and DEFINITELY not the FPU flags...
#	-If I use ctypes, might be better? (The registers)

def usage(imm):
	imm.log("Usage: !taint cmd <param>")
	imm.log("	step")
	imm.log("	trace")
	imm.log("	list")
	imm.log("	reg/rreg")
	imm.log("	mem/rmem")

def main(args):
	if not args:
		return "Usage: !taint cmd <param>"
	if(args[0] == 'trace'): return ttrace()
	if(args[0] == 'step'):
		try:    steps = int(args[1])
		except: steps = 1
		return ttrace(steps)
	if(args[0] == 'clear'): 
		tgen(True)
		return "Map cleared"
	#try:
	if(args[0] == 't'): return ttest() #Debug command
	if(args[0] == 'st'): return tscripttest() #Debug command
	if(args[0] == 'list'): return tlist()
	if(args[0] == 'reg'  and len(args)>1): return treg(args[1].upper(), True)
	if(args[0] == 'rreg' and len(args)>1): return treg(args[1].upper(), False)
	if(args[0] == 'mem'  and len(args)>2): return tmem(int(args[1]), int(args[2]), True)
	if(args[0] == 'rmem' and len(args)>2): return tmem(int(args[1]), int(args[2]), False)
	#except: pass
	return "Invalid command"


"""Commands"""
def tscripttest():
    #Tests for all functionality
	imm = Debugger()
	tmap = tgen()

def ttest():
	imm = Debugger()
	tmap = tgen(True)
	treg('EAX', True)
	ttrace(1)
	tlist()

def tgen(force = False):
	imm  = Debugger()
	tmap = imm.getKnowledge('taintmap')
	if(not tmap or force):
		tmap = TaintMap()
		imm.addKnowledge('taintmap', tmap, True)
	return tmap

def tlist():
	imm   = Debugger()
	tmap  = tgen()
	tregs = tmap.allreg()
	tmem  = tmap.allmem()
	
	imm.log("-----")
	imm.log("Registers")
	for i in tregs:
		if(not any(tregs[i])): continue
		imm.log("   " + [key for key, value in REG_MAP.items() if value == i | REGB_32BIT][0] + ":" + str(tregs[i]))
	imm.log("Memory")
	for i in tmem:
		imm.log("   " + hex(i) + ":" + str(tmem[i]))
	return ""

def treg(x, t):
	imm  = Debugger()
	tmap = tgen()
	
	try:
		i = REGSZ_MAP[REG_MAP[x] & REGB_SIZEMASK]
		tmap.setreg(REG_MAP[x], list(TMMDA_MAP[i] if t else TMMDN_MAP[i]))
		imm.addKnowledge('taintmap', tmap, True)
		return "Taint " + ("set" if t else "cleared")
	except: return "Invalid register"

def tmem(x, y, t):
	imm  = Debugger()
	tmap = tgen()
	try:
		sz = []
		for i in range(0, y): sz.append(TMM_ALL if t else TMM_NONE)
		tmap.setmem(x, sz)
		imm.addKnowledge('taintmap', tmap, True)
		return "Taint " + ("set" if t else "cleared")
	except: return "Invalid memory address"

def ttrace(steps = -1):
	imm  = Debugger()
	tmap = tgen()
	if(imm.getStatus() == 0 or imm.getStatus() == 4): return "Not running!"

	regs  = imm.getRegs();
	stack = []
	stack.append(imm.getFunctionBegin(regs['EIP'])) #FIXME: Might not always be right

	imm.log(" " * (len(stack) - 1) + "<" + hex(regs['EIP']) + ">")

    #This loop runs until the code returns to the caller
	while(len(stack) and imm.getStatus() != 0 and imm.getStatus() != 4): #EIP points to next instr
		imm.stepIn() #Instr is now execd. Regs aren't updated yet!
		steps -= 1
		opdata = OpData(regs, imm.disasm(regs['EIP'])) #Parse
		regs  = imm.getRegs();

		#If the opcode was successfully parsed
		if(opdata.valid):
			_checkTaint(imm, opdata, tmap) #Update our map

	        #Check what type of instr it is and change the stack appropriately
			otype = opdata.opcode.getCmdType()
			if(otype == C_RET):
				stack.pop()
			if(otype == C_CAL): #FIX: Use getCallTree() instead?
				stack.append(regs['EIP'])
				imm.log(" " * (len(stack) - 1) + "<" + hex(regs['EIP']) + ">")
		else:
			imm.log('SKIP')

		imm.addKnowledge('taintmap', tmap, True)
		if(steps == 0): break
	return ""
"""Commands"""

def _checkTaint(imm, op, tmap):
	opmap = []

	#Generate the mask
	for opn in op.operations:
		if  (opn.type == OPRTN_NONE):
			pass
		elif(opn.type == OPRTN_ARITH):
			res = []
			for src in opn.src:
				mask, unused = _getOperandTaint(src, tmap)
				res = _addOperandTaint(res, mask)
			#Taint everything if there's any taint
			if(any(res)):
				res = list(TMMDA_MAP[len(res)])
			opmap.append({'dest':opn.dest, 'mask':res})
		elif(opn.type == OPRTN_OVERWRITE):
			mask, unused = _getOperandTaint(opn.src[0], tmap)
			opmap.append({'dest':opn.dest, 'mask':mask})

	#Apply it!
	for opn in opmap:
		for dest in opn['dest']:
			#if dest size != src size, fix
			mask = opn['mask']
			if(dest.size != len(mask)):
				if(any(mask)):
					mask = list(TMMDA_MAP[dest.size])
			if  (dest.type == OPRND_REG):
				tmap.setreg(dest.data[0], mask)
			elif(dest.type == OPRND_MEM):
				#If the dest is indexed by a tainted reg, taint everything
				unused, index_taint = _getOperandTaint(dest, tmap)
				if(index_taint):
					mask = list(TMMDA_MAP[len(mask)])
				tmap.setmem(dest.addr, mask)

def _addOperandTaint(maska, maskb):
	ret = []
	sz = max(len(maska), len(maskb))

	typea = TMM_ALL if any(maska) else TMM_NONE
	typeb = TMM_ALL if any(maskb) else TMM_NONE
	while(len(maska) < sz): maska.insert(0, typea)
	while(len(maskb) < sz): maskb.insert(0, typeb)

	for i in range(sz):
		ret.append(TMM_ALL if maska[i] or maskb[i] else TMM_NONE)
	return ret

def _getOperandTaint(oprnd, tmap):
	if  (oprnd.type == OPRND_NONE):
		return [], False
	elif(oprnd.type == OPRND_REG):
		return tmap.getreg(oprnd.data[0], list(TMMDA_MAP[oprnd.size])), False
	elif(oprnd.type == OPRND_MEM):
		#If any indexed register is tainted, then consider everything tainted
		if(any([any(tmap.getreg(i, list(TMMDA_MAP[REGSZ_MAP[i & REGB_SIZEMASK]]))) for i in oprnd.data])):
			return list(TMMDA_MAP[oprnd.size]), True
		return tmap.getmem(oprnd.addr, list(TMMDA_MAP[oprnd.size])), False
	elif(oprnd.type == OPRND_CONST):
		return list(TMMDN_MAP[oprnd.size]), False
	elif(oprnd.type == OPRND_CLEAN):
		return list(TMMDN_MAP[oprnd.size]), False
	elif(oprnd.type == OPRND_DIRTY):
		return list(TMMDA_MAP[oprnd.size]), False
