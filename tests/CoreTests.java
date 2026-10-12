package dev.localguard;

import java.io.*;
import java.util.*;

public final class CoreTests {
    private static int assertions;
    private static void check(boolean condition,String message) {
        assertions++;if (!condition) throw new AssertionError(message);
    }
    private static byte[] query(String domain,int type) throws IOException {
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        DataOutputStream output=new DataOutputStream(bytes);
        output.writeShort(0x1234);output.writeShort(0x0100);output.writeShort(1);
        output.writeShort(0);output.writeShort(0);output.writeShort(0);
        for (String label:domain.split("\\.")) { output.writeByte(label.length());output.writeBytes(label); }
        output.writeByte(0);output.writeShort(type);output.writeShort(1);return bytes.toByteArray();
    }
    private static Wire.Packet reverseRoute() {
        Wire.Packet route=new Wire.Packet();route.source=Wire.DNS_IP;route.destination=0x0A4D0001;
        route.sourcePort=53;route.destinationPort=49321;return route;
    }
    private static Wire.Packet client(long sequence,long ack,int flags,byte[] data) {
        byte[] packet=Wire.tcp(reverseRoute(),sequence,ack,flags,data);
        return Wire.parse(packet,packet.length);
    }
    private static long u32(byte[] data,int offset) {
        return ((long)Dns.u16(data,offset)<<16)|Dns.u16(data,offset+2);
    }
    private static long plus(long value,int n) { return (value+n)&0xFFFFFFFFL; }
    public static void main(String[] arguments) throws Exception {
        DomainRules rules=new DomainRules("doubleclick.net\n# comment\n", "0.0.0.0 ads.example.com\r\n*.tracker.test", "good.doubleclick.net");
        check(rules.blocks("ADS.DOUBLECLICK.NET."),"Case/sufijo");
        check(!rules.blocks("notdoubleclick.net"),"No falsa coincidencia");
        check(!rules.blocks("api.good.doubleclick.net"),"Whitelist con prioridad");
        check(rules.blocks("ads.example.com"),"Formato hosts");
        check(!rules.blocks("example.com"),"No bloquear el padre de una regla");
        check(rules.blocks("sub.tracker.test"),"Wildcard");
        check(DomainRules.normalize("mañana.test").equals("xn--maana-pta.test"),"IDN");
        check(DomainRules.normalize("https://example.com")==null,"Rechazar URLs");
        check(DomainRules.normalize("1.2.3.4")==null,"Rechazar IP");
        check(DomainRules.parse("127.0.0.1 localhost\n").isEmpty(),"Ignorar localhost");
        try { DomainRules.parse("ads.example.com bad!domain.test");throw new AssertionError("Regla inválida aceptada"); }
        catch (IllegalArgumentException expected) { assertions++; }
        byte[] q=query("ads.doubleclick.net",1);
        check(Dns.validQuery(q),"Query válida");
        check(Dns.question(q).domain.equals("ads.doubleclick.net"),"QNAME");
        check(Dns.question(q).type==1,"Tipo A");
        byte[] nx=Dns.error(q,3);
        check((Dns.u16(nx,2)&15)==3,"NXDOMAIN");
        check((Dns.u16(nx,2)&0x8100)==0x8100,"QR/RD");
        check(Dns.matches(q,nx),"Conservar pregunta/id");
        check(!Dns.validQuery(nx),"Respuesta no es query");
        byte[] q6=query("ads.doubleclick.net",28);
        check(Dns.question(Dns.error(q6,3)).type==28,"Bloqueo AAAA conserva tipo");
        check((Dns.u16(Dns.truncated(q),2)&0x200)!=0,"Respuesta truncada");
        check(Dns.error(new byte[0],1).length==12,"Error con query vacía");
        byte[] broken=q.clone();broken[12]=(byte)0xC0;broken[13]=12;
        try { Dns.question(broken);throw new AssertionError("Puntero cíclico aceptado"); }
        catch (IOException expected) { assertions++; }
        byte[] opt=Arrays.copyOf(q,q.length+11);Dns.put16(opt,10,1);
        opt[q.length]=0;Dns.put16(opt,q.length+1,41);Dns.put16(opt,q.length+3,4096);
        byte[] limited=Dns.limitEdns(opt);
        check(Dns.u16(limited,q.length+3)==1232,"Limitar EDNS");
        check(Dns.u16(opt,q.length+3)==4096,"No mutar original");
        byte[] datagram=Wire.udp(reverseRoute(),q);Wire.Packet parsed=Wire.parse(datagram,datagram.length);
        check(parsed!=null && parsed.protocol==17,"Leer IP/UDP");
        check(parsed.sourcePort==49321 && parsed.destinationPort==53,"Puertos UDP");
        check(Arrays.equals(parsed.payload,q),"Payload UDP");
        byte[] corrupt=datagram.clone();corrupt[8]^=1;
        check(Wire.parse(corrupt,corrupt.length)==null,"Checksum IPv4");
        corrupt=datagram.clone();corrupt[corrupt.length-1]^=1;
        check(Wire.parse(corrupt,corrupt.length)==null,"Checksum UDP");
        check(Wire.parse(datagram,20)==null,"Longitud inválida");
        byte[] answer=Wire.udp(parsed,nx);
        check(Dns.u16(answer,20)==53 && Dns.u16(answer,22)==49321,"Invertir puertos");
        check(Wire.checksum(answer,0,20,0)==0,"Checksum de respuesta IPv4");
        List<byte[]> written=new ArrayList<>();int[] resolved={0};
        TcpDns tcp=new TcpDns(Runnable::run,written::add,message->{resolved[0]++;return Dns.error(message,3);});
        long clientSequence=0xFFFFFFF0L;
        tcp.accept(client(clientSequence,0,Wire.SYN,new byte[0]));
        check(written.size()==1 && (written.get(0)[33]&255)==(Wire.SYN|Wire.ACK),"SYN/ACK");
        byte[] synAck=written.get(0);long serverNext=plus(u32(synAck,24),1);
        long clientNext=plus(clientSequence,1);
        check(u32(synAck,28)==clientNext,"ACK inicial");
        tcp.accept(client(clientNext,serverNext,Wire.ACK,new byte[0]));
        byte[] frame=new byte[q.length+2];Dns.put16(frame,0,q.length);System.arraycopy(q,0,frame,2,q.length);
        tcp.accept(client(clientNext,serverNext,Wire.ACK|Wire.PSH,Arrays.copyOfRange(frame,0,7)));
        check(resolved[0]==0,"Esperar query TCP completa");
        clientNext=plus(clientNext,7);
        tcp.accept(client(clientNext,serverNext,Wire.ACK|Wire.PSH,Arrays.copyOfRange(frame,7,frame.length)));
        clientNext=plus(clientNext,frame.length-7);
        check(resolved[0]==1,"Resolver TCP una vez");
        ByteArrayOutputStream response=new ByteArrayOutputStream();
        for (byte[] packet:written) if (packet.length>40) response.write(packet,40,packet.length-40);
        byte[] received=response.toByteArray();
        check(received.length==nx.length+2,"Frame DNS/TCP");
        check(Dns.u16(received,0)==nx.length,"Prefijo de longitud TCP");
        check(Arrays.equals(Arrays.copyOfRange(received,2,received.length),nx),"Respuesta TCP completa");
        long responseEnd=plus(serverNext,received.length);
        tcp.accept(client(clientNext,responseEnd,Wire.ACK|Wire.FIN,new byte[0]));
        check((written.get(written.size()-1)[33]&Wire.FIN)!=0,"Cerrar TCP con FIN");
        tcp.accept(client(plus(clientNext,1),plus(responseEnd,1),Wire.ACK,new byte[0]));
        tcp.close();
        System.out.println("OK: "+assertions+" verificaciones del motor DNS/IP/TCP.");
    }
}
