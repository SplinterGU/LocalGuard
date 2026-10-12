package dev.localguard;

import java.net.IDN;
import java.util.*;

public final class DomainRules {
    private final Set<String> blocked;
    private final Set<String> allowed;
    public DomainRules(String base, String custom, String exceptions) {
        blocked = parse(base + "\n" + custom);
        allowed = parse(exceptions);
    }
    public int size() { return blocked.size(); }
    public boolean blocks(String name) {
        String domain = normalize(name);
        if (domain == null || matches(allowed, domain)) return false;
        return matches(blocked, domain);
    }
    private static boolean matches(Set<String> rules, String domain) {
        for (;;) {
            if (rules.contains(domain)) return true;
            int dot = domain.indexOf('.');
            if (dot < 0) return false;
            domain = domain.substring(dot + 1);
        }
    }
    public static Set<String> parse(String text) {
        Set<String> result = new HashSet<>();
        int lineNumber = 0;
        for (String original : text.split("\\r?\\n")) {
            lineNumber++;
            String line = original.split("#", 2)[0].trim();
            if (line.isEmpty()) continue;
            String[] parts = line.split("\\s+");
            int first = 0;
            if (parts[0].equals("0.0.0.0") || parts[0].equals("127.0.0.1") ||
                parts[0].equals("::") || parts[0].equals("::1")) first = 1;
            if (first == parts.length || (first == 0 && parts.length != 1))
                throw new IllegalArgumentException("Línea " + lineNumber + ": usá dominios o formato hosts.");
            for (int i = first; i < parts.length; i++) {
                if (parts[i].equalsIgnoreCase("localhost") ||
                    parts[i].equalsIgnoreCase("localhost.localdomain")) continue;
                String normalized = normalize(parts[i]);
                if (normalized == null)
                    throw new IllegalArgumentException("Línea " + lineNumber + ": dominio inválido: " + parts[i]);
                result.add(normalized);
            }
        }
        return Collections.unmodifiableSet(result);
    }
    public static String normalize(String value) {
        try {
            String domain = value.trim().toLowerCase(Locale.ROOT);
            if (domain.startsWith("*.")) domain = domain.substring(2);
            if (domain.endsWith(".")) domain = domain.substring(0, domain.length() - 1);
            domain = IDN.toASCII(domain, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            if (domain.length() == 0 || domain.length() > 253 || domain.indexOf('.') < 0 ||
                domain.matches("[0-9.]+")) return null;
            for (String label : domain.split("\\.", -1))
                if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-"))
                    return null;
            return domain;
        } catch (IllegalArgumentException exception) { return null; }
    }
}
