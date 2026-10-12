package dev.localguard;

import android.Manifest;
import android.app.*;
import android.content.*;
import android.net.VpnService;
import android.os.*;
import android.graphics.Color;
import android.view.*;
import android.widget.*;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST=10,NOTIFICATIONS_REQUEST=11;
    private final Handler handler=new Handler(Looper.getMainLooper());
    private AppState state;
    private TextView status,counts,log;
    private Button toggle;
    private EditText custom,allow;
    private Spinner resolver;
    private final String[] servers={"1.1.1.1","9.9.9.9","8.8.8.8"};
    private String lastLog="";
    private final Runnable refresh=new Runnable() {
        @Override public void run() { render();handler.postDelayed(this,1000); }
    };
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);state=AppState.get(this);
        LinearLayout page=new LinearLayout(this);page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(20),dp(12),dp(20),dp(20));page.setBackgroundColor(Color.rgb(244,247,250));
        ScrollView scroll=new ScrollView(this);scroll.setFillViewport(true);scroll.addView(page);setContentView(scroll);
        if (Build.VERSION.SDK_INT>=30) {
            scroll.setOnApplyWindowInsetsListener((view,insets)-> {
                android.graphics.Insets system=insets.getInsets(WindowInsets.Type.systemBars()|WindowInsets.Type.ime());
                view.setPadding(system.left,system.top,system.right,system.bottom);return insets;
            });scroll.requestApplyInsets();
        }
        addText(page,"LocalGuard",30);
        addText(page,"Bloqueo local de publicidad y rastreadores por DNS. Sin root.",15);
        status=addText(page,"",16);toggle=button(page,"Activar protección",v->toggleProtection());
        counts=addText(page,"",16);
        button(page,"Reiniciar estadísticas y registro",v-> {
            new AlertDialog.Builder(this).setTitle("Reiniciar estadísticas")
                .setMessage("Se borrarán los contadores y el registro local. Las reglas se conservan.")
                .setNegativeButton("Cancelar",null).setPositiveButton("Reiniciar",(dialog,which)-> { state.reset();render(); }).show();
        });
        addText(page,"Servidor DNS",20);
        resolver=new Spinner(this);
        ArrayAdapter<String> adapter=new ArrayAdapter<>(this,android.R.layout.simple_spinner_item,
            new String[]{"Cloudflare · 1.1.1.1","Quad9 · 9.9.9.9","Google · 8.8.8.8"});
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);resolver.setAdapter(adapter);
        for (int i=0;i<servers.length;i++) if (servers[i].equals(state.resolver)) resolver.setSelection(i);
        if (saved!=null) resolver.setSelection(saved.getInt("draft_resolver",0));
        page.addView(resolver);
        addText(page,"Dominios bloqueados adicionales",20);
        addText(page,"Un dominio por línea. Se incluyen sus subdominios. También acepta archivos hosts pegados. No acepta EasyList.",14);
        custom=editor(page,"ads.ejemplo.com",saved==null?state.preferences.getString("custom",""):saved.getString("draft_custom",""));
        addText(page,"Excepciones: dominios permitidos",20);
        addText(page,"Las excepciones tienen prioridad. Usalas si una aplicación deja de funcionar.",14);
        allow=editor(page,"dominio-necesario.com",saved==null?state.preferences.getString("allow",""):saved.getString("draft_allow",""));
        button(page,"Guardar configuración",v->save());
        button(page,"Ver lista inicial incluida",v-> {
            TextView contents=new TextView(this);contents.setText(state.base);contents.setTextIsSelectable(true);contents.setPadding(dp(16),dp(12),dp(16),dp(12));
            ScrollView list=new ScrollView(this);list.addView(contents);
            new AlertDialog.Builder(this).setTitle("Lista inicial").setView(list).setPositiveButton("Cerrar",null).show();
        });
        addText(page,"Últimas 100 consultas",20);
        log=addText(page,"",12);log.setTypeface(android.graphics.Typeface.MONOSPACE);log.setTextIsSelectable(true);
        addText(page,"Privacidad y límites",20);
        addText(page,"La VPN funciona dentro del teléfono: no hay servidor VPN remoto. Las consultas permitidas se envían al servidor DNS elegido por UDP/TCP, sin cifrado. El registro no se exporta y se borra al cerrar el proceso.\n\nNo bloquea anuncios que compartan dominio con el contenido ni consultas DNS cifradas hechas por las propias apps. No modifica HTTPS. No uses otra VPN simultáneamente. Desactivá DNS privado para obtener un filtrado predecible. No actives «Bloquear conexiones sin VPN»: esta VPN solo enruta DNS.\n\nLa lista inicial es pequeña; ampliarla puede romper servicios. Las reglas y contadores se guardan en el almacenamiento privado de la app.",14);
        render();
    }
    private int dp(int value) { return (int)(value*getResources().getDisplayMetrics().density+0.5f); }
    private TextView addText(LinearLayout page,String value,int size) {
        TextView view=new TextView(this);view.setText(value);view.setTextSize(size);view.setTextColor(Color.rgb(27,42,56));
        view.setPadding(0,dp(10),0,dp(8));page.addView(view,new LinearLayout.LayoutParams(-1,-2));return view;
    }
    private Button button(LinearLayout page,String title,View.OnClickListener listener) {
        Button view=new Button(this);view.setText(title);view.setAllCaps(false);view.setOnClickListener(listener);
        page.addView(view,new LinearLayout.LayoutParams(-1,-2));return view;
    }
    private EditText editor(LinearLayout page,String hint,String value) {
        EditText editor=new EditText(this);editor.setHint(hint);editor.setText(value);
        editor.setSingleLine(false);editor.setMinLines(3);editor.setMaxLines(8);editor.setGravity(Gravity.TOP);
        editor.setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE|
            android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        editor.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(500000)});
        page.addView(editor,new LinearLayout.LayoutParams(-1,-2));return editor;
    }
    private boolean save() {
        try {
            state.saveRules(custom.getText().toString(),allow.getText().toString(),servers[resolver.getSelectedItemPosition()]);
            Toast.makeText(this,"Configuración guardada; se aplica a las siguientes consultas.",Toast.LENGTH_SHORT).show();render();return true;
        } catch (IllegalArgumentException exception) {
            new AlertDialog.Builder(this).setTitle("Regla inválida").setMessage(exception.getMessage()).setPositiveButton("Aceptar",null).show();return false;
        }
    }
    private void toggleProtection() {
        if (AppState.running || AppState.starting) {
            startService(
                    new Intent(this, GuardService.class)
                            .setAction(GuardService.STOP)
            );
            return;
        }
        if (!save()) return;
        Intent consent=VpnService.prepare(this);
        if (consent!=null) startActivityForResult(consent,VPN_REQUEST);else startWithNotifications();
    }
    private void startWithNotifications() {
        if (Build.VERSION.SDK_INT>=33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},NOTIFICATIONS_REQUEST);
        else startProtection();
    }
    @Override public void onRequestPermissionsResult(int request,String[] permissions,int[] grants) {
        super.onRequestPermissionsResult(request,permissions,grants);
        if (request==NOTIFICATIONS_REQUEST) startProtection();
    }
    private void startProtection() {
        try {
            AppState.starting=true;AppState.error="";
            startForegroundService(new Intent(this,GuardService.class).setAction(GuardService.START));
        } catch (RuntimeException exception) { AppState.starting=false;AppState.error=exception.toString(); }
        render();
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if (request==VPN_REQUEST) {
            if (result==RESULT_OK) startWithNotifications();
            else Toast.makeText(this,"No se autorizó la VPN.",Toast.LENGTH_SHORT).show();
        }
    }
    private void render() {
        String mode=AppState.running?"Protección activa":AppState.starting?"Iniciando…":"Protección detenida";
        status.setText(mode+(AppState.error.isEmpty()?"":"\n"+AppState.error));
        toggle.setText(AppState.running || AppState.starting?"Detener protección":"Activar protección");
        counts.setText("Consultas: "+state.total.get()+"  ·  Bloqueadas: "+state.blocked.get()+"  ·  Errores: "+state.failed.get()+
            "\nDominios en reglas: "+state.rules.size());
        String entries=state.logText();
        if (!entries.equals(lastLog) || log.getText().length()==0) {
            lastLog=entries;log.setText(entries.isEmpty()?"Sin consultas todavía.":entries);
        }
    }
    @Override protected void onSaveInstanceState(Bundle saved) {
        saved.putString("draft_custom",custom.getText().toString());
        saved.putString("draft_allow",allow.getText().toString());
        saved.putInt("draft_resolver",resolver.getSelectedItemPosition());
        super.onSaveInstanceState(saved);
    }
    @Override protected void onResume() { super.onResume();handler.removeCallbacks(refresh);handler.post(refresh); }
    @Override protected void onPause() { handler.removeCallbacks(refresh);super.onPause(); }
    @Override protected void onDestroy() { handler.removeCallbacks(refresh);super.onDestroy(); }
}
