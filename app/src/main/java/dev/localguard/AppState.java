package dev.localguard;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

public final class AppState {
    public static volatile boolean running=false,starting=false;
    public static volatile String error="";
    private static AppState instance;
    public final SharedPreferences preferences;
    public final AtomicLong total=new AtomicLong(),blocked=new AtomicLong(),failed=new AtomicLong();
    public volatile DomainRules rules;
    public volatile String resolver;
    public final String base;
    private final Deque<String> logs=new ArrayDeque<>();
    private AppState(Context context) {
        preferences=context.getSharedPreferences("localguard",Context.MODE_PRIVATE);
        total.set(preferences.getLong("total",0));blocked.set(preferences.getLong("blocked",0));
        failed.set(preferences.getLong("failed",0));
        try (InputStream stream=context.getAssets().open("domains.txt")) {
            ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] buffer=new byte[4096];int n;
            while ((n=stream.read(buffer))!=-1) output.write(buffer,0,n);
            base=output.toString(StandardCharsets.UTF_8.name());
        } catch (IOException exception) { throw new IllegalStateException("No se pudo abrir la lista",exception); }
        reload();
    }
    public static synchronized AppState get(Context context) {
        if (instance==null) instance=new AppState(context.getApplicationContext());
        return instance;
    }
    public void reload() {
        rules=new DomainRules(base,preferences.getString("custom",""),preferences.getString("allow",""));
        resolver=preferences.getString("resolver","1.1.1.1");
    }
    public void saveRules(String custom,String allow,String selectedResolver) {
        DomainRules checked=new DomainRules(base,custom,allow);
        if (!Arrays.asList("1.1.1.1","9.9.9.9","8.8.8.8").contains(selectedResolver))
            throw new IllegalArgumentException("Resolver no válido");
        preferences.edit().putString("custom",custom).putString("allow",allow)
            .putString("resolver",selectedResolver).apply();
        rules=checked;resolver=selectedResolver;
    }
    public synchronized void log(String domain,String result) {
        String time=new SimpleDateFormat("HH:mm:ss",Locale.ROOT).format(new Date());
        logs.addFirst(time+"  "+result+"  "+domain);
        while (logs.size()>100) logs.removeLast();
    }
    public synchronized String logText() { return String.join("\n",logs); }
    public void persist() {
        preferences.edit().putLong("total",total.get()).putLong("blocked",blocked.get())
            .putLong("failed",failed.get()).apply();
    }
    public synchronized void reset() {
        total.set(0);blocked.set(0);failed.set(0);logs.clear();persist();
    }
}
