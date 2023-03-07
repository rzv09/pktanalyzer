import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Utils {

    public static byte[] readFile(String file) throws IOException {
        Path path = Paths.get(file);
        byte[] fileContents =  Files.readAllBytes(path);

//        StringBuilder result = new StringBuilder();
//        for (byte aByte: fileContents) {
//            result.append(String.format("%02x", aByte));
//        }

        return  fileContents;
    }

    /** ETHER */
    public static String setDestinationMAC(byte[] packet) {
        StringBuilder result = new StringBuilder();
        for (int i=0; i<6; i++) {
            result.append(String.format("%02x", packet[i]));
            result.append(':');
        }
        return result.substring(0, result.length()-1);
    }

    public static String setSourceMAC(byte[] packet) {
        StringBuilder result = new StringBuilder();
        for (int i=6; i<12; i++) {
            result.append(String.format("%02x", packet[i]));
            result.append(':');
        }
        return result.substring(0, result.length()-1);
    }

     public static String setEtherType(byte[] packet) {
         StringBuilder result = new StringBuilder();
         for (int i=12; i<14; i++) {
             result.append(String.format("%02x", packet[i]));
         }
         return result.toString();
     }

    /** IP */
     public static int setIPVersion(byte[] packet) {
         int ipv = packet[14] >> 4;
         return ipv;
     }

     public static int setHeaderLen(byte[] packet) {
        int mask = 0b1111;
        int headerw = packet[14] & mask;
        return headerw * 4;
     }

     public static int setTotalLength(byte[] packet) {
//         int mask = 0b0000000011111111;
//         int res = packet[17] & mask;
//         res = packet[16] | res;
//         return res;
         byte b1 = packet[16];
         byte b2 = packet[17];

         return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
     }

     public static int setIpId(byte[] packet) {
         byte b1 = packet[18];
         byte b2 = packet[19];

         return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
     }

     public static int setDSCP(byte[] packet) {
         byte b1 = packet[15];
         b1 >>= 2;
         return b1;
     }

     public static int setECN(byte[] packet) {
         byte b1 = packet[15];
         int mask = 0b00000011;
         return b1 & mask;
     }

     public static int setDFflag(byte[] packet) {
         return packet[20] >> 6;
     }

     public static int setMFflag(byte[] packet) {
         int mask = 0b00100000;
         return packet[20] & mask;
     }

     public static int setFragOffset(byte[] packet) {
         byte b1 = packet[20];
//         byte test = 0b01000101;
//         byte test2 = 0b01000101;
//         b1 <<= 3;
         byte b2 = packet[21];
         int mask = 0b00011111;
         int tmp = (b1 & mask);

         return ((tmp << 8 )| (b2 & 0xFF)) & 0xffff;
     }

     public static int setTTL(byte[] packet) {
         return packet[22] & 0xFF;
     }

     public static int setProtocol(byte[] packet) {
         return packet[23] & 0xFF;
     }

     public static String chooseProtocol(int protocol) {
         if (protocol == 6) return protocol + " (TCP)";
         else if (protocol == 1) return protocol + " (ICMP)";
         else if (protocol == 17) return protocol + " (UDP)";
         else return "Unsupported protocol...";
     }

     public static String setHeaderChecksum(byte[] packet) {
         byte b1 = packet[24];
         byte b2 = packet[25];
         StringBuilder result = new StringBuilder();
         result.append(String.format("%02x", ((b1 << 8) | (b2 & 0xFF)) & 0xffff));
         return "0x" + result;
     }

     public static String setSourceIP(byte[] packet) {
         String result = "";
         for (int i=26; i<30; i++) {
             int tmp = packet[i] & 0xFF;
             result = result + tmp + ".";
         }
         return result.substring(0, result.length()-1);
     }

    public static String setDestinationIP(byte[] packet) {
        String result = "";
        for (int i=30; i<34; i++) {
            int tmp = packet[i] & 0xFF;
            result = result + tmp + ".";
        }
        return result.substring(0, result.length()-1);
    }

    public static int setOptionsOffset(int headerLength) {
         if (headerLength > 20) {
             int optionsLen = headerLength - 20;
             return 34 + optionsLen;
         }
         // if IP packet has no options start parsing data from 34th bit
         else return 34;
    }
    public static String setIPv4Options(byte[] packet, int headerLength) {
         if (headerLength > 20) {
//             StringBuilder result = new StringBuilder();
//             result.append("Options: ");
//             int optionsLen = headerLength - 20;
//             for (int i = 34; i < 34+optionsLen; i++) {
//                 result.append(String.format("%02x", packet[i]));
//             }
//             return result.toString();
             return "Options present";
         }
         else {
             return "No options";
         }
    }

    /* ICMP Header Methods */

    public static int setICMPType(byte[] packet, int offset) {
        return packet[offset] & 0xFF;
    }

    public static int setICMPCode(byte[] packet, int offset) {
        return packet[offset+1] & 0xFF;
    }

    public static String setICMPCheckSum(byte[] packet, int offset) {
        byte b1 = packet[offset + 2];
        byte b2 = packet[offset + 3];
        StringBuilder result = new StringBuilder();
        result.append(String.format("%02x", ((b1 << 8) | (b2 & 0xFF)) & 0xffff));
        return "0x" + result;
    }

    /* TCP Header Methods */

    public static int setTCPSourcePort(byte[] packet, int offset) {
        byte b1 = packet[offset];
        byte b2 = packet[offset+1];

        return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
    }

    public static int setTCPDestPort(byte[] packet, int offset) {
        byte b1 = packet[offset+2];
        byte b2 = packet[offset+3];

        return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
    }

    public static int setSequenceNum(byte[] packet, int offset) {
        byte b1 = packet[offset+4];
        byte b2 = packet[offset+5];
        byte b3 = packet[offset+6];
        byte b4 = packet[offset+7];

        return ((b1&0xFF) << 24) | ((b2 &0xFF)<< 16) | ((b3&0xFF) << 8) | ((b4 & 0xFF));
    }
    public static int setAckNum(byte[] packet, int offset) {
        byte b1 = packet[offset+8];
        byte b2 = packet[offset+9];
        byte b3 = packet[offset+10];
        byte b4 = packet[offset+11];

        return ((b1&0xFF) << 24) | ((b2 &0xFF)<< 16) | ((b3&0xFF) << 8) | ((b4 & 0xFF));
    }

    public static int setTCPDataOffset(byte[] packet, int offset) {
        int tmp = ((packet[offset+12] & 0xFF) >> 4) & 0xFF;
        return tmp * 4;
    }

    public static int setTCPUrg(byte[] packet, int offset) {
        int mask = 0b00100000;
        byte b1 = packet[offset+13];
        return (b1&0xFF & mask) >> 5;
    }

    public static int setTCPAck(byte[] packet, int offset) {
        int mask = 0b00010000;
        byte b1 = packet[offset+13];
        return (b1&0xFF & mask) >> 4;
    }
    public static int setTCPPush(byte[] packet, int offset) {
        int mask = 0b00001000;
        byte b1 = packet[offset+13];
        return (b1&0xFF & mask) >> 3;
    }
    public static int setTCPReset(byte[] packet, int offset) {
        int mask = 0b00000100;
        byte b1 = packet[offset+13];
        return (b1&0xFF & mask) >> 2;
    }
    public static int setTCPSyn(byte[] packet, int offset) {
        int mask = 0b00000010;
        byte b1 = packet[offset+13];
        return (b1&0xFF & mask) >> 1;
    }
    public static int setTCPFin(byte[] packet, int offset) {
        int mask = 0b00000001;
        byte b1 = packet[offset+13];
        return b1&0xFF & mask;
    }

    public static int setWindowSize(byte[] packet, int offset) {
        byte b1 = packet[offset+14];
        byte b2 = packet[offset+15];

        return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
    }

    public static String setTCPChecksum(byte[] packet, int offset) {
        byte b1 = packet[offset + 16];
        byte b2 = packet[offset + 17];
        StringBuilder result = new StringBuilder();
        result.append(String.format("%02x", ((b1 << 8) | (b2 & 0xFF)) & 0xffff));
        return "0x" + result;
    }

    public static int setTCPUrgPointer(byte[] packet, int offset) {
        byte b1 = packet[offset+18];
        byte b2 = packet[offset+19];

        return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
    }

    public static String setTCPOptions(int dataOffset) {
        if (dataOffset > 20) {
            return "Options present";
        }
        else {
            return "No options";
        }
    }

    public static String setTCPData(byte[] packet, int dataOffset, int offset, int IPHeaderLen) {
        int start = offset + dataOffset;
        int end = packet.length - 14 - IPHeaderLen - dataOffset;
        StringBuilder result = new StringBuilder();
        // data more than 64 bits;
        if ((end - start) > 64){
            for (int i = start; i<start+64; i++) {
                result.append(String.format("%02x", packet[i]));
            }
        }
        else {
            for (int i = start; i<packet.length; i++) {
                result.append(String.format("%02x", packet[i]));
            }
        }
        return result + "";
    }

    /* UDP Methods */

    public static int setUDPSourcePort(byte[] packet, int offset) {
        byte b1 = packet[offset];
        byte b2 = packet[offset+1];

        return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
    }

    public static int setUDPDestinationPort(byte[] packet, int offset) {
        byte b1 = packet[offset+2];
        byte b2 = packet[offset+3];

        return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
    }

    public static int setUDPLength(byte[] packet, int offset) {
        byte b1 = packet[offset+4];
        byte b2 = packet[offset+5];

        return ((b1 << 8) | (b2 & 0xFF)) & 0xffff;
    }

    public static String setUDPChecksum(byte[] packet, int offset) {
        byte b1 = packet[offset+6];
        byte b2 = packet[offset+7];

        StringBuilder result = new StringBuilder();
        result.append(String.format("%02x", ((b1 << 8) | (b2 & 0xFF)) & 0xffff));
        return "0x" + result;
    }

    public static String setUDPData(byte[] packet, int dataOffset, int offset, int IPHeaderLen) {
        int start = offset + dataOffset;
        int end = packet.length - 14 - IPHeaderLen - dataOffset;
        StringBuilder result = new StringBuilder();
        // data more than 64 bits;
        if ((end - start) > 64){
            for (int i = start; i<start+64; i++) {
                result.append(String.format("%02x", packet[i]));
            }
        }
        else {
            for (int i = start; i<packet.length; i++) {
                result.append(String.format("%02x", packet[i]));
            }
        }
        return result + "";
    }

}
