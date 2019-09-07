from Crypto.Cipher import AES, DES
from MultipartPostHandler import MultipartPostHandler
from Tools.Directories import resolveFilename, SCOPE_PLUGINS
import base64, binascii, os, random, re, urllib2

def decryptDlc(infile):
    links = []
    f = open(resolveFilename(SCOPE_PLUGINS) + 'Extensions/RSDownloader/container/key', 'r')
    a = f.read()
    f.close()
    o = DES.new('1ikp0r{a', DES.MODE_ECB)
    d = o.decrypt(a)
    d = d.strip('#')
    k = d[:16]
    i = d[16:32]
    u = d[32:]
    obj = AES.new(k, AES.MODE_CBC, i)
    dlc = open(infile, 'r')
    data = dlc.read()
    dlc.close()
    dlckey = data[-88:]
    dlcdata = data[:-88]
    dlcdata = base64.standard_b64decode(dlcdata)
    rc = urllib2.urlopen(u + dlckey).read()
    rc = re.search('<rc>(.+)</rc>', rc).group(1)
    rc = base64.standard_b64decode(rc)
    dlckey = obj.decrypt(rc)
    obj = AES.new(dlckey, AES.MODE_CBC, dlckey)
    data = base64.standard_b64decode(obj.decrypt(dlcdata))
    base64_links = re.findall('<url>(.+?)</url>', data)
    for link in base64_links[1:]:
        decryptedUrl = base64.standard_b64decode(link)
        links.append(decryptedUrl)

    return links


def decryptCcf(infile):
    opener = urllib2.build_opener(MultipartPostHandler)
    tempdlc_content = opener.open('http://service.jdownloader.net/dlcrypt/getDLC.php', {'src': 'ccf', 'filename': 'test.ccf', 'upload': open(infile, 'rb')}).read()
    random.seed()
    tempdlc_name = '/tmp/' + str(random.randint(0, 100)) + '-tmp.dlc'
    while os.path.exists(tempdlc_name):
        os.path.exists(tempdlc_name)
        tempdlc_name = '/tmp/' + str(random.randint(0, 100)) + '-tmp.dlc'
    else:
        os.path.exists(tempdlc_name)

    tempdlc = open(tempdlc_name, 'w')
    tempdlc.write(re.search('<dlc>(.*)</dlc>', tempdlc_content, re.DOTALL).group(1))
    tempdlc.close
    return tempdlc_name


def decryptRsdf(infile):
    links = []
    Key = binascii.unhexlify('8C35192D964DC3182C6F84F3252239EB4A320D2500000000')
    IV = binascii.unhexlify('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
    IV_Cipher = AES.new(Key, AES.MODE_ECB)
    IV = IV_Cipher.encrypt(IV)
    obj = AES.new(Key, AES.MODE_CFB, IV)
    rsdf = open(infile, 'r')
    data = rsdf.read()
    data = binascii.unhexlify(('').join(data.split()))
    data = data.splitlines()
    for link in data:
        link = base64.b64decode(link)
        link = obj.decrypt(link)
        decryptedUrl = link.replace('CCF: ', '')
        links.append(decryptedUrl)

    rsdf.close()
    return links


def decrypt(infile):
    try:
        if infile.lower().endswith('.rsdf'):
            infile.lower().endswith('.rsdf')
            return decryptRsdf(infile)
        if infile.lower().endswith('.ccf'):
            infile = decryptCcf(infile)
            return decryptDlc(infile)
        if infile.lower().endswith('.dlc'):
            return decryptDlc(infile)
    except:
        return

    return
