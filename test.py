from pyEWF import E01, Ex01;
from os.path import splitext;
import hashlib;
import binascii;
import time;
import sys;
start = time.clock();
name = sys.argv;
if(not len(name) == 2):
	print("Incorrect arguments!");
	sys.exit();
nm,ex = splitext(name[1]);
if(ex.startswith('.Ex')):
	a = Ex01(name[1].replace('\\','\\\\'));
elif(ex.startswith('.E')):
	a = E01(name[1].replace('\\','\\\\'));
else:
	print("Not a valid file!");
	sys.exit();
b = bytearray(2000000);
c = 0;
old = 0;
m = hashlib.md5();
s = hashlib.sha1();
while(c + 2000000 < a.Size):
	a.myRead( b, c, 2000000);
	m.update(b);
	s.update(b);
	c += 2000000;
	if(c > old + 1000000000):
		old = c;
		print(str(old / 1000000000) + ' GB');
a.myRead(b, c, a.Size-c);
ed = int(a.Size-c);
d = b[0:ed];
m.update(d);
s.update(d);
end = time.clock();

print(binascii.hexlify(a.MD5));
print(m.hexdigest());
print(binascii.hexlify(a.SHA1));
print(s.hexdigest());
print(str((end - start)/60) + ' Min');
