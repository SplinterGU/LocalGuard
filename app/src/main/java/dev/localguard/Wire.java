package dev.localguard;

import java.util.Arrays;

public final class Wire {
    public static final int DNS_IP = 0x0A4D0002;
    public static final int FIN=1, SYN=2, RST=4, PSH=8, ACK=16;
    public static final class Packet {
        public int source, destination, sourcePort, destinationPort, protocol, flags, window;
        public long sequence, acknowledgment;
        public byte[] payload;
    }
    private static int u16(byte[] data, int offset) { return Dns.u16(data, offset); }
    private static int i32(byte[] data, int offset) {
        return ((data[offset] & 255) << 24) | ((data[offset+1] & 255) << 16) |
               ((data[offset+2] & 255) << 8) | (data[offset+3] & 255);
    }
    private static void put32(byte[] data, int offset, long value) {
        for (int i=3;i>=0;i--) { data[offset+i]=(byte)value; value >>>= 8; }
    }
    public static Packet parse(byte[] bytes, int length) {
        if (length < 28 || (bytes[0] & 0xF0) != 0x40) return null;
        int header=(bytes[0]&15)*4, total=u16(bytes,2);
        if (header<20 || total>length || total<header+8 || (u16(bytes,6)&0x3FFF)!=0) return null;
        if (checksum(bytes,0,header,0)!=0) return null;
        Packet packet=new Packet();
        packet.source=i32(bytes,12); packet.destination=i32(bytes,16); packet.protocol=bytes[9]&255;
        if (packet.destination!=DNS_IP || (packet.protocol!=17 && packet.protocol!=6)) return null;
        packet.sourcePort=u16(bytes,header); packet.destinationPort=u16(bytes,header+2);
        if (packet.destinationPort!=53) return null;
        int pseudo=pseudoSum(packet.source,packet.destination,packet.protocol,total-header);
        int payload;
        if (packet.protocol==17) {
            int udpLength=u16(bytes,header+4);
            if (udpLength<8 || header+udpLength!=total) return null;
            if (u16(bytes,header+6)!=0 && checksum(bytes,header,udpLength,pseudo)!=0) return null;
            payload=header+8;
        } else {
            if (total<header+20) return null;
            int tcpHeader=((bytes[header+12]&255)>>>4)*4;
            if (tcpHeader<20 || header+tcpHeader>total || checksum(bytes,header,total-header,pseudo)!=0) return null;
            packet.sequence=i32(bytes,header+4)&0xFFFFFFFFL;
            packet.acknowledgment=i32(bytes,header+8)&0xFFFFFFFFL;
            packet.flags=bytes[header+13]&255; packet.window=u16(bytes,header+14);
            payload=header+tcpHeader;
        }
        packet.payload=Arrays.copyOfRange(bytes,payload,total);
        return packet;
    }
    public static byte[] udp(Packet request, byte[] payload) {
        byte[] bytes=ip(request,17,8+payload.length);
        Dns.put16(bytes,24,8+payload.length);
        System.arraycopy(payload,0,bytes,28,payload.length);
        finish(bytes,request,17,6); return bytes;
    }
    public static byte[] tcp(Packet request,long sequence,long acknowledgment,int flags,byte[] payload) {
        byte[] bytes=ip(request,6,20+payload.length);
        put32(bytes,24,sequence); put32(bytes,28,acknowledgment);
        bytes[32]=0x50; bytes[33]=(byte)flags; Dns.put16(bytes,34,32768);
        System.arraycopy(payload,0,bytes,40,payload.length);
        finish(bytes,request,6,16); return bytes;
    }
    private static byte[] ip(Packet request,int protocol,int transportLength) {
        byte[] bytes=new byte[20+transportLength]; bytes[0]=0x45;
        Dns.put16(bytes,2,bytes.length); Dns.put16(bytes,6,0x4000); bytes[8]=64; bytes[9]=(byte)protocol;
        put32(bytes,12,request.destination); put32(bytes,16,request.source);
        Dns.put16(bytes,20,request.destinationPort); Dns.put16(bytes,22,request.sourcePort);
        return bytes;
    }
    private static void finish(byte[] bytes,Packet request,int protocol,int checkOffset) {
        int value=checksum(bytes,20,bytes.length-20,pseudoSum(request.destination,request.source,protocol,bytes.length-20));
        if (protocol==17 && value==0) value=0xFFFF;
        Dns.put16(bytes,20+checkOffset,value);
        Dns.put16(bytes,10,checksum(bytes,0,20,0));
    }
    private static int pseudoSum(int source,int destination,int protocol,int length) {
        return (source>>>16)+(source&65535)+(destination>>>16)+(destination&65535)+protocol+length;
    }
    public static int checksum(byte[] bytes,int offset,int length,int sum) {
        int end=offset+length;
        while (offset+1<end) { sum+=u16(bytes,offset); offset+=2; }
        if (offset<end) sum+=(bytes[offset]&255)<<8;
        while ((sum>>>16)!=0) sum=(sum&65535)+(sum>>>16);
        return (~sum)&65535;
    }
}
