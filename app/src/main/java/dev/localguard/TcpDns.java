package dev.localguard;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.Executor;

public final class TcpDns {
    public interface Sink { void write(byte[] packet); }
    public interface Resolver { byte[] resolve(byte[] query); }
    private static final byte[] EMPTY=new byte[0];
    private static final long MASK=0xFFFFFFFFL;
    private final Map<String,Session> sessions=new HashMap<>();
    private final SecureRandom random=new SecureRandom();
    private final Executor executor; private final Sink sink; private final Resolver resolver;
    private static final class Segment {
        byte[] bytes; long end,time; int retries;
        Segment(byte[] bytes,long end) { this.bytes=bytes;this.end=end;time=now(); }
    }
    private static final class Session {
        Wire.Packet route; long recv,send,acked,last;
        int window=32768,offset,queuedBytes;
        boolean established,remoteFin,finSent,busy;
        ByteArrayOutputStream incoming=new ByteArrayOutputStream();
        Deque<byte[]> queries=new ArrayDeque<>(),outgoing=new ArrayDeque<>();
        Deque<Segment> pending=new ArrayDeque<>();
    }
    public TcpDns(Executor executor,Sink sink,Resolver resolver) {
        this.executor=executor;this.sink=sink;this.resolver=resolver;
    }
    private static long now() { return System.nanoTime()/1000000; }
    private static long add(long value,int n) { return (value+n)&MASK; }
    private static long delta(long a,long b) { return (a-b)&MASK; }
    private static String key(Wire.Packet p) { return p.source+":"+p.sourcePort; }
    public synchronized void accept(Wire.Packet packet) {
        String key=key(packet); Session session=sessions.get(key);
        if ((packet.flags&Wire.RST)!=0) { sessions.remove(key);return; }
        if ((packet.flags&Wire.SYN)!=0) {
            if (session!=null && !session.established && session.recv==add(packet.sequence,1)) {
                if (!session.pending.isEmpty()) sink.write(session.pending.peek().bytes);
                return;
            }
            if (session!=null) reset(key,session);
            if (sessions.size()>=64) return;
            session=new Session(); session.route=packet; session.recv=add(packet.sequence,1);
            session.send=random.nextInt()&MASK;session.acked=session.send;
            session.window=packet.window;session.last=now();sessions.put(key,session);
            emit(session,Wire.SYN|Wire.ACK,EMPTY,true);return;
        }
        if (session==null) {
            sink.write(Wire.tcp(packet,packet.acknowledgment,
                add(packet.sequence,packet.payload.length+((packet.flags&Wire.FIN)!=0?1:0)),Wire.RST|Wire.ACK,EMPTY));
            return;
        }
        session.last=now();
        if ((packet.flags&Wire.ACK)!=0) {
            long acknowledged=delta(packet.acknowledgment,session.acked);
            long outstanding=delta(session.send,session.acked);
            if (acknowledged>outstanding) { ack(session);return; }
            session.acked=packet.acknowledgment;session.window=packet.window;
            while (!session.pending.isEmpty() && delta(session.pending.peek().end,session.acked)>0x7FFFFFFFL)
                session.pending.remove();
            while (!session.pending.isEmpty() && session.pending.peek().end==session.acked)
                session.pending.remove();
            if (!session.established && session.acked==session.send) session.established=true;
            if (session.finSent && session.pending.isEmpty()) { sessions.remove(key);return; }
        }
        if (!session.established) return;
        if (packet.payload.length>0 || (packet.flags&Wire.FIN)!=0) {
            if (packet.sequence!=session.recv || session.remoteFin) { ack(session);flush(session);return; }
            if (session.incoming.size()+packet.payload.length>65537) { reset(key,session);return; }
            session.incoming.write(packet.payload,0,packet.payload.length);
            session.recv=add(session.recv,packet.payload.length);
            byte[] input=session.incoming.toByteArray();int offset=0;
            while (input.length-offset>=2) {
                int length=Dns.u16(input,offset);
                if (length<12) { reset(key,session);return; }
                if (input.length-offset<length+2) break;
                if (session.queries.size()>=8) { reset(key,session);return; }
                session.queries.add(Arrays.copyOfRange(input,offset+2,offset+2+length));offset+=length+2;
            }
            if (offset>0) {
                session.incoming.reset();session.incoming.write(input,offset,input.length-offset);
            }
            if ((packet.flags&Wire.FIN)!=0) {
                session.remoteFin=true;session.recv=add(session.recv,1);
                if (session.incoming.size()!=0) { reset(key,session);return; }
            }
            ack(session);startQuery(key,session);
        }
        flush(session);
    }
    private void startQuery(String key,Session session) {
        if (session.busy || session.queries.isEmpty()) return;
        byte[] query=session.queries.remove();session.busy=true;
        try {
            executor.execute(()-> {
                byte[] response;
                try { response=resolver.resolve(query); }
                catch (RuntimeException exception) { response=Dns.error(query,2); }
                synchronized (TcpDns.this) {
                    if (sessions.get(key)!=session) return;
                    session.busy=false;
                    if (response==null || response.length>65535) response=Dns.error(query,2);
                    byte[] frame=new byte[response.length+2];Dns.put16(frame,0,response.length);
                    System.arraycopy(response,0,frame,2,response.length);
                    if (session.queuedBytes+frame.length>131074) { reset(key,session);return; }
                    session.outgoing.add(frame);session.queuedBytes+=frame.length;
                    flush(session);startQuery(key,session);
                }
            });
        } catch (RuntimeException exception) { session.busy=false;reset(key,session); }
    }
    private void flush(Session session) {
        while (!session.outgoing.isEmpty()) {
            long capacity=session.window-delta(session.send,session.acked);
            if (capacity<=0) return;
            byte[] first=session.outgoing.peek();
            int count=(int)Math.min(Math.min(1200,capacity),first.length-session.offset);
            byte[] data=Arrays.copyOfRange(first,session.offset,session.offset+count);
            emit(session,Wire.ACK|Wire.PSH,data,true);
            session.offset+=count;session.queuedBytes-=count;
            if (session.offset==first.length) { session.outgoing.remove();session.offset=0; }
        }
        if (session.remoteFin && !session.busy && session.queries.isEmpty() && !session.finSent) {
            session.finSent=true;emit(session,Wire.ACK|Wire.FIN,EMPTY,true);
        }
    }
    private void ack(Session session) { emit(session,Wire.ACK,EMPTY,false); }
    private void emit(Session session,int flags,byte[] payload,boolean track) {
        byte[] bytes=Wire.tcp(session.route,session.send,session.recv,flags,payload);
        int advance=payload.length+((flags&(Wire.SYN|Wire.FIN))!=0?1:0);
        session.send=add(session.send,advance);
        if (track) session.pending.add(new Segment(bytes,session.send));
        sink.write(bytes);
    }
    private void reset(String key,Session session) {
        sink.write(Wire.tcp(session.route,session.send,session.recv,Wire.RST|Wire.ACK,EMPTY));sessions.remove(key);
    }
    public synchronized void tick() {
        long time=now();
        Iterator<Map.Entry<String,Session>> iterator=sessions.entrySet().iterator();
        while (iterator.hasNext()) {
            Session session=iterator.next().getValue();
            if (time-session.last>45000) { iterator.remove();continue; }
            if (!session.pending.isEmpty()) {
                Segment first=session.pending.peek();
                if (time-first.time>1500) {
                    if (++first.retries>5) { iterator.remove();continue; }
                    first.time=time;sink.write(first.bytes);
                }
            }
        }
    }
    public synchronized void close() { sessions.clear(); }
}
