#reference: https://www.codeproject.com/Tips/612847/Generate-a-quick-and-easy-custom-pcap-file-using-P

import binascii, sys

def writeByteStringToFile(bytestring, filename):
  bytelist = bytestring.split()  
  bytes = binascii.a2b_hex(''.join(bytelist))
  bitout = open(filename, 'wb')
  bitout.write(bytes)

#Global header for pcap 2.4
pcapGlobalHeader =   ('D4 C3 B2 A1 '   
                      '02 00 '         #File format major revision (i.e. pcap <2>.4)  
                      '04 00 '         #File format minor revision (i.e. pcap 2.<4>)   
                      '00 00 00 00 '     
                      '00 00 00 00 '     
                      'FF FF 00 00 '     
                      '01 00 00 00 ')

#pcap packet header that must preface every packet
pcapPacketHeaderPrefix =   ('AA 77 9F 47 '     
                            '90 A2 04 00 '     
                            'XX XX XX XX '   #Frame Size (little endian) 
                            'YY YY YY YY ')  #Frame Size (little endian)

def packetsGenerator(rawDataBytes):
  byteIdx = 0
  while byteIdx < len(rawDataBytes):
    ethHeaderLen = 14
    ipLenOffset = ethHeaderLen + 2
    ipLen = int(f'0x{rawDataBytes[byteIdx + ipLenOffset]}{rawDataBytes[byteIdx + ipLenOffset + 1]}', 16)
    packetLen = ethHeaderLen + ipLen
    yield rawDataBytes[byteIdx:byteIdx + packetLen]
    byteIdx = packetLen
  return

def generateIcapFromRawPackets(fileName):
  f = open(fileName, 'r')
  rawData = ' '.join([(line[7:-1] if line[-1] == '\n' else line[7:]) for line in f.readlines()])
  f.close()
  rawDataBytes = rawData.split(' ')
  icap = [pcapGlobalHeader]
  for packetBytes in packetsGenerator(rawDataBytes):
    hexStr = "%08x"%len(packetBytes)
    littleEndianHexStr = hexStr[6:] + " " + hexStr[4:6] + " " + hexStr[2:4] + " " + hexStr[:2]
    pcapPacketHeader = pcapPacketHeaderPrefix.replace('XX XX XX XX', littleEndianHexStr)
    pcapPacketHeader = pcapPacketHeader.replace('YY YY YY YY', littleEndianHexStr)
    icap.append(pcapPacketHeader)
    icap.append(' '.join(packetBytes))

  writeByteStringToFile(''.join(icap).lower(), f'{fileName.split(".")[0]}.icap')
  return

if __name__ == '__main__':
  if len(sys.argv) < 2:
    raise Exception('Must provide file name of raw packets')

  generateIcapFromRawPackets(sys.argv[1])

