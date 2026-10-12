package dev.localguard;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.IOException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public final class GuardService extends VpnService {

    public static final String START = "dev.localguard.START";
    public static final String STOP = "dev.localguard.STOP";

    private static final String TAG = "LocalGuard";
    private static final String CHANNEL = "dns_filter";
    private static final int NOTIFICATION_ID = 71;

    private static final byte[] WAKE_BYTE = {1};

    private final Handler mainHandler =
            new Handler(Looper.getMainLooper());

    private AppState state;
    private volatile Run current;

    private static final class Run {
        ParcelFileDescriptor tun;

        final FileDescriptor wakeRead = new FileDescriptor();
        final FileDescriptor wakeWrite = new FileDescriptor();

        final ArrayBlockingQueue<byte[]> outgoing =
                new ArrayBlockingQueue<>(256);

        final AtomicBoolean released = new AtomicBoolean(false);

        Thread reader;
        ThreadPoolExecutor workers;
        ScheduledExecutorService timer;
        Upstream upstream;
        TcpDns tcp;

        volatile boolean closed;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        state = AppState.get(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            requestStop();
            stopSelf();
            return START_NOT_STICKY;
        }

        if (current != null) {
            return START_NOT_STICKY;
        }

        AppState.starting = true;
        AppState.error = "";

        Run run = new Run();
        current = run;

        try {
            foreground();

            if (VpnService.prepare(this) != null) {
                throw new IOException(
                        "Falta autorizar la VPN. Abrí LocalGuard y pulsá Activar."
                );
            }

            run.upstream = new Upstream(this);

            Network physical = run.upstream.network();

            if (Build.VERSION.SDK_INT >= 28) {
                ConnectivityManager manager =
                        getSystemService(ConnectivityManager.class);

                LinkProperties properties =
                        manager.getLinkProperties(physical);

                if (properties != null
                        && properties.getPrivateDnsServerName() != null) {
                    throw new IOException(
                            "Desactivá DNS privado personalizado "
                                    + "en Ajustes de Android antes de iniciar."
                    );
                }
            }

            Os.socketpair(
                    OsConstants.AF_UNIX,
                    OsConstants.SOCK_STREAM | OsConstants.SOCK_NONBLOCK,
                    0,
                    run.wakeRead,
                    run.wakeWrite
            );

            run.tun = new Builder()
                    .setSession("LocalGuard · filtro DNS local")
                    .setMtu(1500)
                    .addAddress("10.77.0.1", 32)
                    .addDnsServer("10.77.0.2")
                    .addRoute("10.77.0.2", 32)
                    .allowFamily(OsConstants.AF_INET6)
                    .setBlocking(false)
                    .establish();

            if (run.tun == null) {
                throw new IOException(
                        "Android no pudo establecer la VPN."
                );
            }

            run.workers = new ThreadPoolExecutor(
                    4,
                    8,
                    30,
                    TimeUnit.SECONDS,
                    new ArrayBlockingQueue<>(128),
                    runnable -> {
                        Thread thread = new Thread(
                                runnable,
                                "localguard-dns"
                        );
                        thread.setDaemon(true);
                        return thread;
                    },
                    new ThreadPoolExecutor.AbortPolicy()
            );

            run.tcp = new TcpDns(
                    run.workers,
                    packet -> enqueue(run, packet),
                    query -> resolve(run, query)
            );

            run.timer = Executors.newSingleThreadScheduledExecutor();

            run.timer.scheduleAtFixedRate(
                    () -> {
                        if (!run.closed) {
                            run.tcp.tick();
                        }
                    },
                    1,
                    1,
                    TimeUnit.SECONDS
            );

            run.timer.scheduleAtFixedRate(
                    state::persist,
                    15,
                    15,
                    TimeUnit.SECONDS
            );

            run.reader = new Thread(
                    () -> packetLoop(run),
                    "localguard-tun"
            );

            AppState.running = true;
            AppState.starting = false;

            run.reader.start();

            Log.i(TAG, "Protección iniciada");

        } catch (Exception exception) {
            AppState.error = message(exception);
            Log.e(TAG, "No se pudo iniciar la protección", exception);

            requestStop();
            stopSelf();
        }

        return START_NOT_STICKY;
    }

    private void foreground() {
        NotificationManager manager =
                getSystemService(NotificationManager.class);

        NotificationChannel channel = new NotificationChannel(
                CHANNEL,
                "Protección DNS",
                NotificationManager.IMPORTANCE_LOW
        );

        channel.setDescription(
                "Servicio VPN local de LocalGuard"
        );

        manager.createNotificationChannel(channel);

        PendingIntent open = PendingIntent.getActivity(
                this,
                0,
                new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE
                        | PendingIntent.FLAG_UPDATE_CURRENT
        );

        PendingIntent stop = PendingIntent.getService(
                this,
                1,
                new Intent(this, GuardService.class).setAction(STOP),
                PendingIntent.FLAG_IMMUTABLE
                        | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Notification notification =
                new Notification.Builder(this, CHANNEL)
                        .setSmallIcon(R.drawable.ic_shield)
                        .setContentTitle("LocalGuard activo")
                        .setContentText(
                                "Filtrado DNS local · tocá para abrir"
                        )
                        .setContentIntent(open)
                        .setOngoing(true)
                        .setCategory(Notification.CATEGORY_SERVICE)
                        .addAction(
                                new Notification.Action.Builder(
                                        null,
                                        "Detener",
                                        stop
                                ).build()
                        )
                        .build();

        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            );
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private void packetLoop(Run run) {
        FileDescriptor tunFd = run.tun.getFileDescriptor();

        StructPollfd tunPoll = new StructPollfd();
        tunPoll.fd = tunFd;

        StructPollfd wakePoll = new StructPollfd();
        wakePoll.fd = run.wakeRead;
        wakePoll.events = (short) OsConstants.POLLIN;

        StructPollfd[] descriptors = {tunPoll, wakePoll};

        byte[] buffer = new byte[32767];

        try {
            while (!run.closed) {
                flushOutgoing(run, tunFd);

                tunPoll.events = (short) (
                        OsConstants.POLLIN
                                | (run.outgoing.isEmpty()
                                ? 0 : OsConstants.POLLOUT)
                );

                tunPoll.revents = 0;
                wakePoll.revents = 0;

                try {
                    Os.poll(descriptors, 1000);
                } catch (ErrnoException exception) {
                    if (exception.errno == OsConstants.EINTR) {
                        continue;
                    }
                    throw exception;
                }

                if (run.closed) {
                    break;
                }

                if ((wakePoll.revents & OsConstants.POLLIN) != 0) {
                    drainWake(run);
                }

                int errors = OsConstants.POLLERR
                        | OsConstants.POLLHUP
                        | OsConstants.POLLNVAL;

                if ((tunPoll.revents & errors) != 0
                        || (wakePoll.revents & errors) != 0) {
                    throw new IOException(
                            "La interfaz VPN o su canal de control se cerró."
                    );
                }

                if ((tunPoll.revents & OsConstants.POLLIN) != 0) {
                    readPackets(run, tunFd, buffer);
                }

                flushOutgoing(run, tunFd);
            }

        } catch (Exception exception) {
            if (!run.closed) {
                Log.e(TAG, "Error en el hilo del túnel", exception);

                mainHandler.post(() -> {
                    if (current == run) {
                        AppState.error = message(exception);
                        requestStop();
                        stopSelf();
                    }
                });
            }

        } finally {
            releaseResources(run);
        }
    }

    private void readPackets(
            Run run,
            FileDescriptor tunFd,
            byte[] buffer
    ) throws IOException, ErrnoException {

        for (int i = 0; i < 32 && !run.closed; i++) {
            int length;

            try {
                length = Os.read(
                        tunFd,
                        buffer,
                        0,
                        buffer.length
                );
            } catch (ErrnoException exception) {
                if (exception.errno == OsConstants.EAGAIN) {
                    return;
                }
                if (exception.errno == OsConstants.EINTR) {
                    continue;
                }
                throw exception;
            }

            if (length == 0) {
                throw new IOException(
                        "El túnel VPN llegó al final del flujo."
                );
            }

            Wire.Packet packet = Wire.parse(buffer, length);

            if (packet == null) {
                continue;
            }

            if (packet.protocol == 6) {
                run.tcp.accept(packet);
                continue;
            }

            try {
                run.workers.execute(() -> {
                    if (run.closed) {
                        return;
                    }

                    byte[] response = resolve(run, packet.payload);

                    if (response.length > 1232) {
                        response = Dns.truncated(packet.payload);
                    }

                    enqueue(run, Wire.udp(packet, response));
                });

            } catch (RejectedExecutionException exception) {
                if (!run.closed) {
                    state.total.incrementAndGet();
                    state.failed.incrementAndGet();
                    state.log("cola DNS", "SATURADO");

                    enqueue(
                            run,
                            Wire.udp(
                                    packet,
                                    Dns.error(packet.payload, 2)
                            )
                    );
                }
            }
        }
    }

    private void enqueue(Run run, byte[] packet) {
        if (run.closed || current != run) {
            return;
        }

        if (!run.outgoing.offer(packet)) {
            state.failed.incrementAndGet();
            state.log("cola de salida", "SATURADO");
            return;
        }

        wake(run);
    }

    private void flushOutgoing(
            Run run,
            FileDescriptor tunFd
    ) throws IOException, ErrnoException {

        for (int i = 0; i < 32 && !run.closed; i++) {
            byte[] packet = run.outgoing.peek();

            if (packet == null) {
                return;
            }

            int written;

            try {
                written = Os.write(
                        tunFd,
                        packet,
                        0,
                        packet.length
                );
            } catch (ErrnoException exception) {
                if (exception.errno == OsConstants.EAGAIN) {
                    return;
                }
                if (exception.errno == OsConstants.EINTR) {
                    continue;
                }
                throw exception;
            }

            if (written != packet.length) {
                throw new IOException(
                        "Escritura incompleta de un paquete al túnel."
                );
            }

            run.outgoing.poll();
        }
    }

    private static void wake(Run run) {
        if (!run.wakeWrite.valid()) {
            return;
        }

        try {
            Os.write(
                    run.wakeWrite,
                    WAKE_BYTE,
                    0,
                    WAKE_BYTE.length
            );
        } catch (Exception ignored) {
            // El canal es no bloqueante. Si está lleno ya hay
            // una señal pendiente; si está cerrado, el hilo termina.
        }
    }

    private static void drainWake(
            Run run
    ) throws IOException, ErrnoException {

        byte[] buffer = new byte[128];

        for (int i = 0; i < 32; i++) {
            try {
                int read = Os.read(
                        run.wakeRead,
                        buffer,
                        0,
                        buffer.length
                );

                if (read == 0) {
                    return;
                }

            } catch (ErrnoException exception) {
                if (exception.errno == OsConstants.EAGAIN) {
                    return;
                }
                if (exception.errno == OsConstants.EINTR) {
                    continue;
                }
                throw exception;
            }
        }
    }

    private byte[] resolve(Run run, byte[] query) {
        if (run.closed) {
            return Dns.error(query, 2);
        }

        state.total.incrementAndGet();

        String domain = "consulta inválida";

        try {
            if (!Dns.validQuery(query)) {
                throw new IOException("Consulta DNS no válida.");
            }

            Dns.Question question = Dns.question(query);
            domain = question.domain;

            if (state.rules.blocks(domain)) {
                state.blocked.incrementAndGet();
                state.log(domain, "BLOQUEADO");
                return Dns.error(query, 3);
            }

            byte[] response = run.upstream.resolve(
                    query,
                    state.resolver
            );

            if (!run.closed) {
                state.log(domain, "PERMITIDO");
            }

            return response;

        } catch (Exception exception) {
            if (!run.closed) {
                state.failed.incrementAndGet();
                state.log(domain, "ERROR DNS");
            }

            return Dns.error(query, 2);
        }
    }

    private void requestStop() {
        Run run = current;
        current = null;

        AppState.running = false;
        AppState.starting = false;

        stopForeground(STOP_FOREGROUND_REMOVE);

        if (run == null) {
            return;
        }

        Log.i(TAG, "Parada solicitada");

        run.closed = true;
        wake(run);

        if (run.reader == null || !run.reader.isAlive()) {
            Thread cleanup = new Thread(
                    () -> releaseResources(run),
                    "localguard-cleanup"
            );
            cleanup.start();
        }
    }

    private void releaseResources(Run run) {
        if (!run.released.compareAndSet(false, true)) {
            return;
        }

        run.closed = true;

        // Primero se retira la VPN. No esperamos a los workers.
        if (run.tun != null) {
            try {
                run.tun.close();
                Log.i(TAG, "TUN cerrado");
            } catch (IOException exception) {
                Log.w(TAG, "Error al cerrar el TUN", exception);
            }
        }

        closeDescriptor(run.wakeRead);
        closeDescriptor(run.wakeWrite);

        if (run.timer != null) {
            run.timer.shutdownNow();
        }

        if (run.workers != null) {
            run.workers.shutdownNow();
        }

        if (run.upstream != null) {
            run.upstream.close();
        }

        if (run.tcp != null) {
            run.tcp.close();
        }

        run.outgoing.clear();
        state.persist();

        Log.i(TAG, "Recursos de la protección liberados");
    }

    private static void closeDescriptor(FileDescriptor descriptor) {
        if (!descriptor.valid()) {
            return;
        }

        try {
            Os.close(descriptor);
        } catch (ErrnoException ignored) {
        }
    }

    private static String message(Exception exception) {
        String text = exception.getMessage();

        return text == null
                ? exception.getClass().getSimpleName()
                : text;
    }

    @Override
    public void onRevoke() {
        requestStop();
        stopSelf();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        requestStop();
        super.onDestroy();
    }
}