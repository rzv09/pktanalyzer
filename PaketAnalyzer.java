import java.io.IOException;

public class PaketAnalyzer {
    int packetSize;
    String destinationMAC;
    String sourceMAC;
    byte[] data;
    String etherType;
    int ipv;
    int headerSize;
    int totalLengthIP;
    int IpID;
    int DSCPval;
    int ECN;
    int DF;
    int MF;
    int fragOffset;
    int TTL;
    int Protocol;
    String ProtocolStr;
    String HeaderCheckSum;
    String SourceIPAddr;
    String DestIPAddr;
    String IPOpt;
    int OptionsOffset;

    /* ICMP Fields */
    int ICMPtype;
    int ICMPcode;
    String ICMPCheckSum;

    /* TCP Fields */
    int TCPSourcePort;
    int TCPDestPort;
    int TCPSeqNum;
    int TCPAckNum;
    int TCPDataOffset;
    int TCPUrg;
    int TCPAck;
    int TCPPush;
    int TCPReset;
    int TCPFin;
    int TCPSyn;
    String Urg;
    String Ack;
    String Push;
    String Reset;
    String Fin;
    String Syn;
    int TCPWindowSize;
    String TCPChecksum;
    int TCPurgPointer;
    String TCPOptions;
    /* data field shared across packets */
    String hexData;
    /* UDP fields */
    int UDPSourcePort;
    int UDPDestinationPort;
    int UDPLength;
    String UDPCheckSum;

    public PaketAnalyzer(String filename) throws IOException {
        data = Utils.readFile(filename);
    }

    public void processEther() {
        /* ETHER */
        packetSize = data.length;
        destinationMAC = Utils.setDestinationMAC(data);
        sourceMAC = Utils.setSourceMAC(data);
        etherType = Utils.setEtherType(data);
        /* END ETHER */
    }

    public void processIPv4() {
        ipv = Utils.setIPVersion(data);
        headerSize = Utils.setHeaderLen(data);
        totalLengthIP = Utils.setTotalLength(data);
        IpID = Utils.setIpId(data);
        DSCPval = Utils.setDSCP(data);
        ECN = Utils.setECN(data);
        DF = Utils.setDFflag(data);
        MF = Utils.setMFflag(data);
        fragOffset = Utils.setFragOffset(data);
        Protocol = Utils.setProtocol(data);
        ProtocolStr = Utils.chooseProtocol(Protocol);
        HeaderCheckSum = Utils.setHeaderChecksum(data);
        SourceIPAddr = Utils.setSourceIP(data);
        DestIPAddr = Utils.setDestinationIP(data);
        TTL = Utils.setTTL(data);
        IPOpt = Utils.setIPv4Options(data, headerSize);
        OptionsOffset = Utils.setOptionsOffset(headerSize);
    }

    public void processICMP() {
        ICMPtype = Utils.setICMPType(data, OptionsOffset);
        ICMPcode = Utils.setICMPCode(data, OptionsOffset);
        ICMPCheckSum = Utils.setICMPCheckSum(data, OptionsOffset);

    }

    public void processTCP() {
        TCPSourcePort = Utils.setTCPSourcePort(data, OptionsOffset);
        TCPDestPort = Utils.setTCPDestPort(data, OptionsOffset);
        TCPSeqNum = Utils.setSequenceNum(data, OptionsOffset);
        // !!! IMPORTANT
        TCPAckNum = Utils.setAckNum(data, OptionsOffset);
        TCPDataOffset = Utils.setTCPDataOffset(data, OptionsOffset);
        TCPUrg = Utils.setTCPUrg(data, OptionsOffset);
        TCPAck = Utils.setTCPAck(data, OptionsOffset);
        TCPPush = Utils.setTCPPush(data, OptionsOffset);
        TCPReset = Utils.setTCPReset(data, OptionsOffset);
        TCPSyn = Utils.setTCPSyn(data, OptionsOffset);
        TCPFin = Utils.setTCPFin(data, OptionsOffset);
        TCPWindowSize = Utils.setWindowSize(data, OptionsOffset);
        TCPChecksum = Utils.setTCPChecksum(data, OptionsOffset);
        TCPurgPointer = Utils.setTCPUrgPointer(data, OptionsOffset);
        TCPOptions = Utils.setTCPOptions(TCPDataOffset);
        hexData = Utils.setTCPData(data, TCPDataOffset, OptionsOffset, headerSize);
    }

    public void processUDP() {
        UDPSourcePort = Utils.setUDPSourcePort(data, OptionsOffset);
        UDPDestinationPort = Utils.setUDPDestinationPort(data, OptionsOffset);
        UDPLength = Utils.setUDPLength(data, OptionsOffset);
        UDPCheckSum = Utils.setUDPChecksum(data, OptionsOffset);
        hexData = Utils.setUDPData(data, 8, OptionsOffset, headerSize);
    }

    public String getProtocolStr() {
        return ProtocolStr;
    }

    public int getProtocol() {
        return Protocol;
    }

    public String printEther() {
         return String.format( """
                ETHER:\t----- Ether Header -----
                ETHER:\t
                ETHER:\tPacket size = %2d bytes
                ETHER:\tDestination = %s
                ETHER:\tSource = %s
                ETHER:\tEthertype = %s (IP)
                ETHER:\t
                """, packetSize, destinationMAC, sourceMAC, etherType);
    }

    public String printIP() {
        return String.format("""
                IP:\t----- IP Header -----
                IP:\t
                IP:\tVersion = %2d
                IP:\tHeader length = %2d bytes
                IP:\tDSCP = %2d
                IP:\tECN = %2d
                IP:\tTotal length = %2d bytes
                IP:\tIdentification = %2d
                IP:\tFlags:
                IP:\t\tDF = %2d
                IP:\t\tMF = %2d
                IP:\tFragment offset = %2d bytes
                IP:\tTime to live = %2d seconds/hops
                IP:\tProtocol = %s
                IP:\tHeader checksum = %s
                IP:\tSource address = %s
                IP:\tDestination address = %s
                IP:\t%s
                IP:\t
                """, ipv, headerSize, DSCPval, ECN, totalLengthIP, IpID, DF, MF, fragOffset, TTL, ProtocolStr,
                HeaderCheckSum, SourceIPAddr, DestIPAddr, IPOpt);
    }

    public String printICMP() {
        return String.format("""
                ICMP:\t----- ICMP Header -----
                ICMP:\t
                ICMP:\tType = %2d
                ICMP:\tCode = %2d
                ICMP:\tChecksum = %s
                ICMP:\t
                """, ICMPtype, ICMPcode, ICMPCheckSum);
    }

    public void setTCPFlagsStr() {
        if (TCPUrg > 0) this.Urg = "Urgent pointer";
        else this.Urg = "No urgent pointer";
        if (TCPAck > 0) this.Ack = "Acknowledgement";
        else this.Ack = "No acknowledgement";
        if (TCPPush > 0) this.Push = "Push";
        else this.Push = "No push";
        if (TCPReset > 0) this.Reset = "Reset";
        else this.Reset = "No reset";
        if (TCPSyn > 0) this.Syn = "Syn";
        else this.Syn = "No Syn";
        if (TCPFin > 0) this.Fin = "Fin";
        else this.Fin = "No Fin";
    }
    public String printTCPFlags() {
        String bin = "" + TCPUrg + TCPAck + TCPPush + TCPReset + TCPSyn + TCPFin;
        setTCPFlagsStr();
        return String.format("""
                Flags = %s
                \t\t\t..%1d. .... = %s
                \t\t\t...%1d .... = %s
                \t\t\t.... %1d... = %s
                \t\t\t.... .%1d.. = %s
                \t\t\t.... ..%1d. = %s
                \t\t\t.... ...%1d = %s""", "0x" + Integer.toHexString(Integer.parseInt(bin, 2)), TCPUrg, Urg, TCPAck, Ack,
                TCPPush, Push, TCPReset, Reset, TCPSyn, Syn, TCPFin, Fin);
    }

//    public String printTCPData() {
//
//    }

    public String printTCP() {
        String flags = printTCPFlags();
        return String.format("""
                TCP:\t----- TCP Header -----
                TCP:\t
                TCP:\tSource port = %2d
                TCP:\tDestination port = %2d
                TCP:\tSequence number = %s
                TCP:\tAcknowledgement number = %s
                TCP:\tData offset = %2d bytes
                TCP:\t%s
                TCP:\tWindow = %2d
                TCP:\tChecksum = %s
                TCP:\tUrgent pointer = %2d
                TCP:\t%s
                TCP:\tData: (first 64 bytes)
                %s
                """, TCPSourcePort, TCPDestPort, Integer.toUnsignedString(TCPSeqNum), Integer.toUnsignedString(TCPAckNum),
                TCPDataOffset, flags, TCPWindowSize, TCPChecksum,
                TCPurgPointer, TCPOptions, TCPdataHexdump());
    }

    public String printUPD() {
        return String.format("""
                UDP:\t----- UDP Header -----
                UDP:\t
                UDP:\tSource port = %2d
                UDP:\tDestination port = %2d
                UDP:\tLength = %2d
                UDP:\tChecksum = %s
                UDP:\t
                UDP:\tData: (first 64 bytes)
                %s
                
                """, UDPSourcePort, UDPDestinationPort, UDPLength, UDPCheckSum, UDPdataHexdump());
    }

    public String TCPdataHexdump() {
        int groupCount = 0;
        int charCount = 0;
        int row = 0;
        StringBuilder res = new StringBuilder();
        res.append("TCP:\t");
        for (int i = 0; i<hexData.length(); i++) {
            if (charCount == 4) {
                charCount = 0;
                groupCount++;
                res.append(" ");
            }
            if(groupCount == 8) {
                groupCount = 0;
                res.append("\t\t\t");
                res.append(hexToASCII(row, i));
                row = i;
                res.append("\n");
                res.append("TCP:\t");
                charCount = 0;
//                groupCount++;
            }
            res.append(hexData.charAt(i));
            charCount++;
        }
        res.append("\t\t\t");
        res.append(hexToASCII(row, hexData.length()));
        return res.toString();
    }

    public String UDPdataHexdump() {
        int groupCount = 0;
        int charCount = 0;
        int row = 0;
        StringBuilder res = new StringBuilder();
        res.append("UDP:\t");
        for (int i = 0; i<hexData.length(); i++) {
            if (charCount == 4) {
                charCount = 0;
                groupCount++;
                res.append(" ");
            }
            if(groupCount == 8) {
                groupCount = 0;
                res.append("\t\t\t");
                res.append(hexToASCII(row, i));
                row = i;
                res.append("\n");
                res.append("UDP:\t");
                charCount = 0;
//                groupCount++;
            }
            res.append(hexData.charAt(i));
            charCount++;
        }
        res.append("\t\t\t");
        res.append(hexToASCII(row, hexData.length()));
        return res.toString();
    }

    public String hexToASCII(int start, int end) {
        StringBuilder output = new StringBuilder();
        for (int i = start; i < end; i+=2) {
            String str = hexData.substring(i, i+2);
            int decimal = Integer.parseInt(str, 16);
            output.append((char) decimal);
        }
        return output.toString();
    }

}
