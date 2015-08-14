pyEWF.py

Class E01

	to create --> a = E01('G:\\asdf.E01');
	to read   --> r = a.myRead( output, offset, length );
        output will contain the bytes, r will be the number 
        of bytes read (usually length unless EOF reached)
    a.Size = length of image (not forensic files)
    a.MD5 = stored md5 value
    a.SHA1 = stored sha1 value

Class Ex01

	to create --> a = Ex01('G:\\asdf.Ex01');
	to read   --> r = a.myRead( output, offset, length );
        output will contain the bytes, r will be the number 
        of bytes read (usually length unless EOF reached)
    a.Size = length of image (not forensic files)
    a.MD5 = stored md5 value
    a.SHA1 = stored sha1 value
    
test.py
    
    usage --> python.exe test.py C:\path\to\file.e01(ex01)