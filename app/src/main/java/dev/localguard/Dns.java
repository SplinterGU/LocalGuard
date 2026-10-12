package dev.localguard;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public final class Dns {
    public static final class Question {
        public final String domain;
        public final int type, clazz, end;
        Question(String domain, int type, int clazz, int end) {
            this.domain = domain; this.type = type; this.clazz = clazz; this.end = end;
        }
    }
    private static final class Name {
        final String value; final int end;
        Name(String value, int end) { this.value = value; this.end = end; }
    }
    public static int u16(byte[] data, int offset) {
        return ((data[offset] & 255) << 8) | (data[offset + 1] & 255);
    }
    public static void put16(byte[] data, int offset, int value) {
        data[offset] = (byte)(value >>> 8); data[offset + 1] = (byte)value;
    }
    private static Name name(byte[] data, int start) throws IOException {
        int cursor = start, end = -1, hops = 0;
        StringBuilder name = new StringBuilder();
        Set<Integer> visited = new HashSet<>();
        while (true) {
            if (cursor >= data.length || !visited.add(cursor) || ++hops > 128)
                throw new IOException("Nombre DNS mal formado");
            int length = data[cursor++] & 255;
            if (length == 0) break;
            if ((length & 0xC0) == 0xC0) {
                if (cursor >= data.length) throw new IOException("Puntero incompleto");
                int destination = ((length & 63) << 8) | (data[cursor++] & 255);
                if (destination >= cursor - 2) throw new IOException("Puntero hacia adelante");
                if (end < 0) end = cursor;
                cursor = destination;
                continue;
            }
            if (length > 63 || cursor + length > data.length) throw new IOException("Etiqueta inválida");
            if (name.length() > 0) name.append('.');
            name.append(new String(data, cursor, length, StandardCharsets.US_ASCII));
            cursor += length;
            if (name.length() > 253) throw new IOException("Nombre demasiado largo");
        }
        return new Name(name.toString().toLowerCase(Locale.ROOT), end < 0 ? cursor : end);
    }
    public static Question question(byte[] data) throws IOException {
        if (data.length < 12 || u16(data, 4) != 1) throw new IOException("Se requiere una pregunta DNS");
        Name name = name(data, 12);
        if (name.end + 4 > data.length) throw new IOException("Pregunta incompleta");
        return new Question(name.value, u16(data, name.end), u16(data, name.end + 2), name.end + 4);
    }
    public static boolean validQuery(byte[] data) {
        return data.length >= 12 && (u16(data, 2) & 0xF800) == 0;
    }
    public static byte[] error(byte[] query, int rcode) {
        int end = 12, count = 0;
        try { end = question(query).end; count = 1; } catch (IOException ignored) { }
        byte[] result = new byte[end];
        if (query.length >= 2) System.arraycopy(query, 0, result, 0, 2);
        if (count == 1) System.arraycopy(query, 12, result, 12, end - 12);
        int flags = 0x8080 | (rcode & 15);
        if (query.length >= 4) flags |= u16(query, 2) & 0x0100;
        put16(result, 2, flags); put16(result, 4, count);
        return result;
    }
    public static byte[] truncated(byte[] query) {
        byte[] response = error(query, 0);
        put16(response, 2, u16(response, 2) | 0x0200);
        return response;
    }
    public static boolean matches(byte[] query, byte[] response) {
        try {
            if (response.length < 12 || u16(query, 0) != u16(response, 0) ||
                (u16(response, 2) & 0xF800) != 0x8000) return false;
            Question a = question(query), b = question(response);
            return a.domain.equals(b.domain) && a.type == b.type && a.clazz == b.clazz;
        } catch (IOException | IndexOutOfBoundsException exception) { return false; }
    }
    public static byte[] limitEdns(byte[] query) throws IOException {
        byte[] copy = query.clone();
        int cursor = question(copy).end;
        int records = u16(copy, 6) + u16(copy, 8) + u16(copy, 10);
        if (records > 256) throw new IOException("Demasiados registros");
        for (int i = 0; i < records; i++) {
            Name name = name(copy, cursor); cursor = name.end;
            if (cursor + 10 > copy.length) throw new IOException("Registro incompleto");
            if (u16(copy, cursor) == 41 && u16(copy, cursor + 2) > 1232)
                put16(copy, cursor + 2, 1232);
            int length = u16(copy, cursor + 8); cursor += 10 + length;
            if (cursor > copy.length) throw new IOException("Registro fuera del paquete");
        }
        return copy;
    }
}
