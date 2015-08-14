from os.path import dirname, realpath, isfile, join, splitext;
from os import listdir;
from struct import unpack;
from math import floor;
import zlib;
import binascii;

class Ex01:
	def __init__(self, fileName): #initialize
		######## INITIALIZE ########
		self.fileList = list(); # for holding all files
		self.secOffsets = list(); # for holding offsets
		self.fileName = fileName; # for holding first file
		self.destDir = dirname(realpath(self.fileName)); # for holding directory name
		#self.type2 = 0;
		self.offSecStart = 0;
		self.offStart = 0;
		self.offEnd = 0;
		self.sectorStart = 0;
		self.firstTime = True;
		self.cnt = 0;
		self.blah = 0;
		self.MD5 = bytearray(16);
		self.SHA1 = bytearray(20);
		
		for f in listdir(self.destDir): # get everything in that directory
			a,b = splitext(f); # get the extension
			if(isfile(join(self.destDir,f)) and b.startswith('.E')): # if it is a file and starts with .E
				self.fileList.append(join(self.destDir,f)); # Add file to the list of files
		######## END INITIALIZE #######
		########## Get hash info ##########
		lst = open(self.fileList[-1], 'rb');
		lst.seek(-64,2);
		#print(lst.tell());
		secName = unpack('i', lst.read(4));
		while(not secName[0] == 1):
			tmp = lst.tell()-4;
			if(secName[0] == 8):
				lst.seek(4,1);
				offset = unpack('Q', lst.read(8));
				size = unpack('Q', lst.read(8));
				lst.seek(tmp - size[0]);
				self.MD5 = lst.read(16);
				lst.seek(offset[0]);
			elif(secName[0] == 9):
				lst.seek(4,1);
				offset = unpack('Q', lst.read(8));
				size = unpack('Q', lst.read(8));
				lst.seek(tmp - size[0]);
				self.SHA1 = lst.read(20);
				lst.seek(offset[0]);
			elif(secName[0] == 2):
				lst.seek(4,1);
				offset = unpack('Q', lst.read(8));
				size = unpack('Q', lst.read(8));
				lst.seek(tmp - size[0]);
				#buffr = bytearray(size[0]);
				#lst.readinto(buffr);
				unkb = zlib.decompress(lst.read(size[0]));
				unkb = unkb[2:len(unkb)];
				lines = unkb.decode('utf_16').split('\n');
				cols = lines[2].split('\t');
				vals = lines[3].split('\t');
				i = 0
				for a in cols:
					if(a.replace('\0','') == 'sb'):
						break;
					i += 1;
				self.secPerBlock = float(vals[i].replace('\0',''));
				#print(self.secPerBlock);
				lst.seek(offset[0]);
			else:
				lst.seek(4,1);
				offset = unpack('Q', lst.read(8));
				lst.seek(offset[0]);
			secName = unpack('i', lst.read(4));
		tmp = lst.tell()-4;
		lst.seek(4,1);
		offset = unpack('Q', lst.read(8));
		size = unpack('Q', lst.read(8));
		lst.seek(tmp-size[0]);
		#buffr = bytearray(size[0]);
		#lst.readinto(buffr);
		unkb = zlib.decompress(lst.read(size[0]));
		unkb = unkb[2:len(unkb)];
		lines = unkb.decode().split('\n');
		cols = lines[2].split('\t');
		vals = lines[3].split('\t');
		i = 0
		for a in cols:
			if(a.replace('\0','') == 'ts'):
				break;
			i += 1;
		ii = 0
		for a in cols:
			if(a.replace('\0','') == 'bp'):
				break;
			ii += 1;
		self.Size = float(vals[i].replace('\0',''))*float(vals[ii].replace('\0',''));
		self.bbs = float(vals[ii].replace('\0',''));
		lst.close();
		self.bl = int(self.bbs*self.secPerBlock);
		######### end get hash info ##########
		
		######### Get section offsets ##########
		self.firstTime = True
		self.fileList.sort(reverse=True)
		for fil in self.fileList: # for each file
			lst = open(fil, 'rb'); # open files
			lst.seek(-64,2);
			secName = unpack('i', lst.read(4)); # get first section name
			while(not secName[0] == 1):
				tmp = lst.tell()-4;
				if(secName[0] == 4):
					lst.seek(4,1);
					offset = unpack('Q', lst.read(8));
					size = unpack('Q', lst.read(8));
					pad = unpack('I', lst.read(4));
					lst.seek(36,1);
					lst.seek(tmp-size[0]);
					cnkNum = unpack('Q', lst.read(8));
					cnt = unpack('I', lst.read(4));
					#pad = unpack('I', lst.read(4));
					lst.seek(20,1);
					if(self.firstTime):
						#self.Size = (cnkNum[0]+cnt[0]) * 32768;
						self.firstTime = False;
					self.secOffsets.append([fil, cnkNum[0] * self.bl, (cnkNum[0]+cnt[0]) * self.bl, lst.tell(), cnt[0]]);
					#print(cnt[0]);
					#print(str(pad[0]) + ' ' + str(cnkNum[0]) + ' ' + str(cnkNum[0] * 32768) + ' ' + str((cnkNum[0]+cnt[0]) * 32768));
					lst.seek(offset[0]);
				else:
					lst.seek(4,1);
					offset = unpack('Q', lst.read(8));
					lst.seek(offset[0]);
				secName = unpack('i', lst.read(4));
			lst.close()
		self.secOffsets.sort();
		
	def getFileCount(self, st, ln ):
		tmp = list();
		for a in self.secOffsets:
			if( st <= a[2]):
				if( (st + ln) < a[2]):
					tmp.append(a);
					return tmp;
				else:
					tmp.append(a);
		return tmp;
		
	def myRead(self, variable, start , length ):
		self.firstTime = True;
		i = 0;
		if( start + length > self.secOffsets[-1][2]):
			i = i;
		else:
			l = list();
			l = self.getFileCount(start, length);
			for p in l:
				i = self.readFile(p, start, length, variable, i);
		return i;
		
	def readFile(self, c, off, leng, byt, retPos ):
		firstFill = True;
		toFill = bytearray(8);
		last = bytearray(1);
		retArray = bytearray(1);
		unkb = bytearray(1);
		stdBuff = bytearray(self.bl);
		oldFilled = bytearray(self.bl);
		myStart = 0;
		offset = off - retPos;
		cnt = c[4];
		startPiece = 0;
		if(self.firstTime):
			startPiece = floor((offset - c[1])/self.bl);
			myStart = offset - c[1] - (startPiece * self.bl);
			self.firstTime = False;
		f = open(c[0], 'rb');
		f.seek(c[3]);
		f.seek((startPiece * 16),1);
		cnt -= startPiece;
		
		while( cnt > 0 and leng > 0 and not len(byt) == retPos):
			tmp1 = unpack('Q', f.read(8));
			size = unpack('I', f.read(4))[0];
			flags = unpack('I', f.read(4));
			if(flags[0] == 0):
				print('WHAAAAAAAAT ' + str(flags[0]));
			elif(flags[0] == 1):
				old = f.tell();
				f.seek(tmp1[0]);
				#arr = bytearray(size);
				#f.readinto(arr);
				unkb = bytearray(zlib.decompress(f.read(size)));
				f.seek(old);
				tmp = len(byt)-retPos;
				if(tmp <= len(unkb)-myStart):
					byt[int(retPos):int(retPos+tmp)] = unkb[int(myStart):int(myStart+tmp)];
					retPos = retPos + tmp;
				else:
					byt[int(retPos):int(retPos+(len(unkb)-myStart))] = unkb[int(myStart):int(len(unkb))];
					retPos = retPos + (len(unkb)-myStart);
			elif(flags[0] == 2):
				old = f.tell();
				f.seek(tmp1[0]);
				arr = bytearray(size-4);
				f.readinto(arr);
				f.seek(old);
				tmp = len(byt)-retPos;
				if(tmp <= len(arr)-myStart):
					byt[int(retPos):int(retPos+tmp)] = arr[int(myStart):int(myStart+tmp)];
					retPos = retPos + tmp;
				else:
					byt[int(retPos):int(retPos+(len(arr)-myStart))] = arr[int(myStart):int(len(arr))];
					retPos = retPos + (len(arr)-myStart);
			elif(flags[0] == 3):
				print('WHAAAAAAAAT ' + str(flags[0]));
			elif(flags[0] == 4):
				print('WHAAAAAAAAT ' + str(flags[0]));
			elif(flags[0] == 5):
				f.seek(-16,1)
				tmp2 = bytearray(8);
				f.readinto(tmp2);
				f.seek(8,1);
				###
				if(tmp2 == toFill and not firstFill):
					stdBuff = oldFilled;
				else:
					self.fill(tmp2,stdBuff);
					oldFilled[:] = stdBuff;
					toFill = tmp2
					firstFill = False;
				###
				tmp = len(byt)-retPos;
				if(tmp <= len(stdBuff)-myStart):
					byt[int(retPos):int(retPos+tmp)] = stdBuff[int(myStart):int(myStart+tmp)];
					retPos = retPos + tmp;
				else:
					byt[int(retPos):int(retPos+(len(stdBuff)-myStart))] = stdBuff[int(myStart):int(len(stdBuff))];
					retPos = retPos + (len(stdBuff)-myStart);
			else:
				print('WHAAAAAAAAT ' + str(flags[0]));
			cnt = cnt - 1;
			myStart = 0;
		f.close();
		return retPos;
	
	def fill(self, fillPat, buff):
		i = len(buff);
		b = 0;
		while (i > 0):
			buff[b:b+8] = fillPat;
			i = i - 8;
			b = b + 8;
		
		
		
		
		
		

class E01:
	def __init__(self, fileName): #initialize
		######## INITIALIZE ########
		self.fileList = list(); # for holding all files
		self.secOffsets = list(); # for holding offsets
		self.fileName = fileName; # for holding first file
		self.destDir = dirname(realpath(self.fileName)); # for holding directory name
		self.type2 = 0;
		self.offSecStart = 0;
		self.offStart = 0;
		self.offEnd = 0;
		self.sectorStart = 0;
		self.MD5 = bytearray(16);
		self.SHA1 = bytearray(20);
		self.firstTime = False;
		
		for f in listdir(self.destDir): # get everything in that directory
			a,b = splitext(f); # get the extension
			if(isfile(join(self.destDir,f)) and b.startswith('.E')): # if it is a file and starts with .E
				self.fileList.append(join(self.destDir,f)); # Add file to the list of files
		######## END INITIALIZE #######
		########## Get hash info ##########
		lst = open(self.fileList[-1], 'rb');
		lst.seek(13);
		secName = lst.read(16).decode();
		while(not 'done' in secName):
			if('hash' in secName):
				offset = unpack('Q', lst.read(8));
				lst.seek(8,1);
				lst.seek(44,1);
				self.MD5 = lst.read(16);
				lst.seek(offset[0]);
			elif('digest' in secName):
				offset = unpack('Q', lst.read(8));
				lst.seek(8,1);
				lst.seek(44,1);
				self.MD5 = lst.read(16);
				self.SHA1 = lst.read(20);
				lst.seek(offset[0]);
			else:
				offset = unpack('Q', lst.read(8));
				lst.seek(offset[0]);
			secName = lst.read(16).decode();
		lst.close();
		######### end get hash info ##########
		######### Get section offsets ##########
		self.fileList.sort();
		max = 0;
		for fil in self.fileList: # for each file
			#print(fil);
			lst = open(fil, 'rb'); # open files
			lst.seek(13);
			secName = lst.read(16).decode(); # get first section name
			while(not 'done' in secName and not 'next' in secName):
				#print(fil + secName);
				if('table' in secName and not '2' in secName): # TABLE
					offset = unpack('Q', lst.read(8));
					lst.seek(8,1);
					lst.seek(44,1);
					cnt = unpack('I', lst.read(4));
					if(cnt[0] > max):
						max = cnt[0];
					#print(cnt[0]);
					#if(cnt[0] > 16375 and not self.type2 == 1):
						#self.type2 = 1;
					lst.seek(20,1);
					self.offEnd += cnt[0] * self.byperchunk;
					self.secOffsets.append([fil, self.offSecStart, self.offEnd, lst.tell(), cnt[0], self.secOffset[0], self.sectorStart]);
					self.offSecStart = self.offEnd;
					lst.seek(offset[0]);
				elif('sector' in secName): # SECTOR
					self.sectorStart = lst.tell() - 16;
					self.secOffset = unpack('Q', lst.read(8));
					lst.seek(self.secOffset[0]);
				elif('volume' in secName or 'disk' in secName):
					offset = unpack('Q', lst.read(8));
					lst.seek(52,1);
					lst.seek(8,1);
					self.spc = unpack('I', lst.read(4))[0];
					#print(self.spc);
					self.bps = unpack('I', lst.read(4))[0];
					#print(self.bps);
					self.secs = unpack('I', lst.read(4))[0];
					#print(self.secs);
					self.byperchunk = int(self.spc*self.bps);
					#print(self.byperchunk);
					lst.seek(offset[0]);
				else: # OTHER
					offset = unpack('Q', lst.read(8));
					lst.seek(offset[0]);
				secName = lst.read(16).decode();
			lst.close();
		if(max ==16384):
			self.type2 = 1;
		self.Size = self.secs*self.bps;
		#print(self.Size);
		######### End Get section offsets ##########
		#for a in self.secOffsets:
			#print(str(a[0]) + ' ' + str(a[1]) + ' ' + str(a[2]) + ' ' + str(a[3]) + ' ' + str(a[4]) + ' ' + str(a[5]));

	def getFileCount(self, st, ln ):
		tmp = list();
		for a in self.secOffsets:
			if( st <= a[2]):
				if( (st + ln) < a[2]):
					tmp.append(a);
					return tmp;
				else:
					tmp.append(a);
		return tmp;
		
	def myRead(self, variable, start , length ):
		#print('myread start:' + str(start) + ' length:' + str(length));
		self.firstTime = True;
		i = 0;
		if( start + length > self.secOffsets[-1][2]):
			i = i;
		else:
			l = list();
			l = self.getFileCount(start, length);
			#print(len(l));
			for p in l:
				if(i == len):
					break;
				if(self.type2 == 1):
					i = self.readFile2(p, start, length, variable, i);
				else:
					i = self.readFile(p, start, length, variable, i);
		return i;
		
	
	def readFile(self, c, off, leng, byt, retPos ):
		
		last = bytearray(1);
		retArray = bytearray(1);
		unkb = bytearray(1);
		stdBuff = bytearray(self.byperchunk);
		myStart = 0;
		#print('off: ' + str(off) + ' retPos: ' + str(retPos));
		offset = off - retPos;
		cnt = c[4];
		startPiece = 0;
		if(self.firstTime):
			#startPiece = floor(offset / 32768);
			#myStart = offset - (startPiece * 32768);
			startPiece = floor((offset - c[1])/self.byperchunk);
			myStart = offset - c[1] - (startPiece * self.byperchunk);
			#print('startPiece: ' + str(startPiece));
			self.firstTime = False;
		f = open(c[0], 'rb');
		f.seek(c[3]);
		f.seek((startPiece * 4),1);
		cnt -= startPiece;
		while( cnt > 0 and leng > 0 and not len(byt) == retPos):
			#print(str(cnt) + ' ' + str(leng) + ' ' + str(retPos));
			#input();
			tmp1 = unpack('i', f.read(4));
			a = tmp1[0]
			old = f.tell();
			#print(a);
			if( a < 0):
				a += 2147483647;
				a += 1;
				tmp2 = unpack('i', f.read(4));
				f.seek(a);
				b = tmp2[0];
				if(cnt == 1):
					b = c[5];
				else:
					if(b < 0):
						b += 2147483647+1;
				by = bytearray(b-a);
				f.readinto(by);
				#print(f.tell());
				if(not last == by):
					f.seek(-1*(b-a),1);
					unkb = bytearray(zlib.decompress(f.read(b-a)));
					last[:] = by;
					retArray[:] = unkb;
				else:
					unkb = retArray;
				f.seek(old);
				if( len(unkb) < self.byperchunk ):
					byt[retPos:retPos+len(unkb)] = unkb[myStart:len(unkb)];
					retPos += len(unkb)
					break;
				tmp = len(byt) - retPos;
				if(tmp <=self.byperchunk):
					byt[int(retPos):int(retPos+(tmp-myStart))] = unkb[int(myStart):int(myStart+(tmp-myStart))];
					if(tmp-myStart < 0):
						print('blah1!');
						input();
					retPos += (tmp-myStart);
					leng -= (tmp - myStart);
				else:
					byt[int(retPos):int(retPos+(self.byperchunk-myStart))] = unkb[int(myStart):int(myStart+(self.byperchunk-myStart))];
					if(self.byperchunk-myStart < 0):
						print('blah2!');
						input();
					retPos += self.byperchunk-myStart;
					leng -= self.byperchunk-myStart;
			else:
				f.seek(a);
				#print(f.tell());
				#input();
				#stdBuff = bytearray(32768);
				f.readinto(stdBuff);
				#print(len(stdBuff));
				f.seek(old);
				tmp = len(byt) - retPos;
				if(tmp <= self.byperchunk):
					#print(str(retPos) + ' ' + str(retPos+(tmp-myStart)) + ' ' + str(myStart) + ' ' + str(myStart+(tmp-myStart)));
					byt[int(retPos):int(retPos+(tmp-myStart))] = stdBuff[int(myStart):int(myStart+(tmp-myStart))]
					if(tmp-myStart < 0):
						print('blah3!');
						input();
					retPos += (tmp-myStart);
					leng -= (tmp - myStart);
				else:
					byt[int(retPos):int(retPos+(self.byperchunk-myStart))] = stdBuff[int(myStart):int(myStart+(self.byperchunk-myStart))];
					if(self.byperchunk-myStart < 0):
						print('blah4! myStart: ' + str(myStart));
						input();
					retPos += self.byperchunk-myStart;
					leng -= self.byperchunk-myStart;
			cnt -= 1;
			myStart = 0;
		f.close();
		return retPos;
		
		
	def readFile2(self, c, off, leng, byt, retPos ):
		last = bytearray(1);
		retArray = bytearray(1);
		offAddition = c[6];
		unkb = bytearray(1);
		stdBuff = bytearray(self.byperchunk);
		myStart = 0;
		#print('off: ' + str(off) + ' retPos: ' + str(retPos));
		offset = off - retPos;
		cnt = c[4];
		startPiece = 0;
		if(self.firstTime):
			#startPiece = floor(offset / 32768);
			#myStart = offset - (startPiece * 32768);
			startPiece = floor((offset - c[1])/self.byperchunk);
			myStart = offset - c[1] - (startPiece * self.byperchunk);
			#print('startPiece: ' + str(startPiece));
			self.firstTime = False;
		f = open(c[0], 'rb');
		f.seek(c[3]);
		f.seek((startPiece * 4),1);
		cnt -= startPiece;
		while( cnt > 0 and leng > 0 and not len(byt) == retPos):
			#print(str(cnt) + ' ' + str(leng) + ' ' + str(retPos));
			#input();
			tmp1 = unpack('i', f.read(4));
			a = tmp1[0]
			old = f.tell();
			#print(a);
			if( a < 0):
				a += 2147483647;
				a += 1;
				#print(a);
				a += offAddition;
				#print(a);
				tmp2 = unpack('i', f.read(4));
				f.seek(a);
				#print(f.tell());
				b = tmp2[0];
				if(cnt == 1):
					b = c[5];
				else:
					if(b < 0):
						b += 2147483647+1;
					b += offAddition;
				#print(str(a) + ' ' + str(b));
				by = bytearray(b-a);
				f.readinto(by);
				#print(f.tell());
				if(not last == by):
					f.seek(-1*(b-a),1);
					unkb = bytearray(zlib.decompress(f.read(b-a)));
					last[:] = by;
					retArray[:] = unkb;
				else:
					unkb = retArray;
				f.seek(old);
				if( len(unkb) < self.byperchunk ):
					byt[int(retPos):int(retPos+len(unkb))] = unkb[int(myStart):int(len(unkb))];
					retPos += len(unkb)
					break;
				tmp = len(byt) - retPos;
				#if(tmp <=32768):
				if(tmp < len(unkb)):
					byt[int(retPos):int(retPos+(tmp-myStart))] = unkb[int(myStart):int(myStart+(tmp-myStart))];
					retPos += (tmp - myStart);
					leng -= (tmp - myStart);
				else:
					byt[int(retPos):int(retPos+(len(unkb)-myStart))] = unkb[int(myStart):int(myStart+(len(unkb)-myStart))];
					retPos += len(unkb)-myStart;
					leng -= len(unkb)-myStart;
			else:
				a += offAddition;
				tmp2 = unpack('i', f.read(4));
				f.seek(a);
				b = tmp2[0];
				if(cnt == 1):
					b = c[5];
				else:
					if(b < 0):
						b += 2147483647+1;
					b += offAddition;
				tmpLen = b - a;
				newBuff = bytearray(b-a);
				f.readinto(newBuff);
				f.seek(old);
				tmp = len(byt) - retPos;
				if (len(newBuff) < self.byperchunk):
					byt[int(retPos):int(retPos+(len(newBuff)-4))] = newBuff[int(myStart):int(myStart+(len(newBuff)-4))];
					retPos += len(newBuff)-4;
					break;
				if( tmp < self.byperchunk):
					byt[int(retPos):int(retPos+(tmp - myStart))] = newBuff[int(myStart):int(myStart+(tmp-myStart))];
					retPos += (tmp-myStart);
					leng = (tmp-myStart);
				else:
					byt[int(retPos):int(retPos+(self.byperchunk-myStart))] = newBuff[int(myStart):int(myStart+(self.byperchunk-myStart))];
					retPos += self.byperchunk - myStart;
					leng += self.byperchunk - myStart;
			cnt -= 1;
			myStart = 0;
		f.close();
		return retPos;