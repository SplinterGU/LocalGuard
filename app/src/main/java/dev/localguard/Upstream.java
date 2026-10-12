package dev.localguard;

import android.net.*;
import java.io.*;
import java.net.*;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class Upstream implements Closeable {
    private final GuardService service;
    private final ConnectivityManager connectivity;
    private final Set<Closeable> sockets=ConcurrentHashMap.newKeySet();
    private volatile boolean closed;
    public Upstream(GuardService service) {
        this.service=service;connectivity=service.getSystemService(ConnectivityManager.class);
    }
    public Network network() throws IOException {
        Network active=connectivity.getActiveNetwork();
        if (usable(active)) return active;
        Network fallback=null;
        for (Network candidate:connectivity.getAllNetworks()) {
            if (!usable(candidate)) continue;
            NetworkCapabilities capabilities=connectivity.getNetworkCapabilities(candidate);
            if (capabilities!=null && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return candidate;
            fallback=candidate;
        }
        if (fallback==null) throw new IOException("No hay una red con Internet");
        return fallback;
    }
    private boolean usable(Network network) {
        if (network==null) return false;
        NetworkCapabilities capabilities=connectivity.getNetworkCapabilities(network);
        return capabilities!=null && capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }
    private void track(Closeable socket) throws IOException {
        sockets.add(socket);
        if (closed) { sockets.remove(socket);socket.close();throw new IOException("Servicio detenido"); }
    }
    public byte[] resolve(byte[] query,String primary) throws IOException {
        byte[] outgoing=Dns.limitEdns(query);
        String secondary=primary.equals("1.1.1.1")?"1.0.0.1":primary.equals("9.9.9.9")?"149.112.112.112":"8.8.4.4";
        IOException last=null;
        for (String address:new String[]{primary,secondary}) {
            if (closed) throw new IOException("Servicio detenido");
            try {
                Network network=network();
                byte[] response=outgoing.length>1232?tcp(outgoing,address,network):udp(outgoing,address,network);
                if (!Dns.matches(query,response)) throw new IOException("Respuesta DNS inválida");
                if ((Dns.u16(response,2)&0x0200)!=0) response=tcp(outgoing,address,network);
                if (!Dns.matches(query,response)) throw new IOException("Respuesta DNS TCP inválida");
                return response;
            } catch (IOException exception) { last=exception; }
        }
        throw last!=null?last:new IOException("DNS sin respuesta");
    }
    private byte[] udp(byte[] query,String address,Network network) throws IOException {
        DatagramSocket socket=new DatagramSocket(null);track(socket);
        try {
            if (!service.protect(socket)) throw new IOException("No se pudo proteger el socket UDP");
            network.bindSocket(socket);socket.bind(new InetSocketAddress(0));socket.setSoTimeout(1800);
            socket.connect(InetAddress.getByName(address),53);
            socket.send(new DatagramPacket(query,query.length));
            byte[] buffer=new byte[65535];DatagramPacket reply=new DatagramPacket(buffer,buffer.length);
            socket.receive(reply);return java.util.Arrays.copyOf(buffer,reply.getLength());
        } finally { sockets.remove(socket);socket.close(); }
    }
    private byte[] tcp(byte[] query,String address,Network network) throws IOException {
        Socket socket=new Socket();track(socket);
        try {
            if (!service.protect(socket)) throw new IOException("No se pudo proteger el socket TCP");
            network.bindSocket(socket);socket.connect(new InetSocketAddress(address,53),1800);socket.setSoTimeout(1800);
            DataOutputStream output=new DataOutputStream(socket.getOutputStream());
            output.writeShort(query.length);output.write(query);output.flush();
            DataInputStream input=new DataInputStream(socket.getInputStream());
            int length=input.readUnsignedShort();
            if (length<12) throw new IOException("Respuesta TCP demasiado corta");
            byte[] result=new byte[length];input.readFully(result);return result;
        } finally { sockets.remove(socket);socket.close(); }
    }
    @Override public void close() {
        closed=true;
        for (Closeable socket:sockets) try { socket.close(); } catch (IOException ignored) { }
        sockets.clear();
    }
}
