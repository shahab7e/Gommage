package org.gommage.tv;

import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

import net.freehaven.tor.control.TorControlConnection;

import org.torproject.jni.TorService;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import IPtProxy.Controller;
import IPtProxy.IPtProxy;
import IPtProxy.OnTransportEvents;
import hev.htproxy.TProxyService;

/** Whole-device VPN: Tor (via bridges) behind a tun interface, like the desktop app's whole-system mode. */
public class GommageVpn extends VpnService {
    static final String STOP = "org.gommage.tv.STOP";
    static final int SOCKS = 19050; // not 9050, so Orbot or another Tor app can run alongside
    static final String[] TRANSPORTS = {IPtProxy.Obfs4, IPtProxy.Webtunnel, IPtProxy.Snowflake};

    // State the activity reads; one VPN per process, so static is enough
    static volatile boolean running, connected, failed;
    static volatile long since; // when the tunnel came up, for the timer
    static volatile String status = "Not connected";
    static volatile Runnable onChange;
    static final List<String> log = Collections.synchronizedList(new ArrayList<>());
    private static volatile TorControlConnection ctl;

    private Thread worker;
    private ParcelFileDescriptor tun;
    private ServiceConnection torConn;
    // One per process, as IPtProxy asks: a second Controller breaks gomobile's refs ("trackGoRef called with Java refnum")
    private static Controller pt;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            shutdown();
            stopSelf();
        } else if (!running) {
            running = true;
            failed = false;
            worker = new Thread(this::connect, "gommage-connect");
            worker.start();
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() { // another VPN took over, or the user turned us off in Settings
        shutdown();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        shutdown();
        super.onDestroy();
    }

    static void newIdentity() {
        new Thread(() -> {
            try {
                ctl.signal("NEWNYM");
                note("New identity: new Tor circuits for new connections");
            } catch (Exception e) {
                note("New identity failed: " + e.getMessage());
            }
        }).start();
    }

    private void connect() {
        try {
            SharedPreferences prefs = getSharedPreferences("gommage", MODE_PRIVATE);
            set("Starting Tor…");
            if (pt == null) pt = new Controller(getCacheDir().getPath(), false, false, "WARN", new OnTransportEvents() {
                public void connected(String name) { }
                public void error(String name, Exception e) { note(name + ": " + e.getMessage()); }
                public void stopped(String name, Exception e) { }
            });
            Map<String, String> snow = params(firstLine(asset("builtin.txt"), "snowflake"));
            pt.setSnowflakeBrokerUrl(snow.getOrDefault("url", ""));
            pt.setSnowflakeFrontDomains(snow.getOrDefault("fronts", ""));
            pt.setSnowflakeIceServers(snow.getOrDefault("ice", ""));
            StringBuilder torrc = new StringBuilder("SocksPort " + SOCKS + "\nDisableNetwork 1\nAvoidDiskWrites 1\n");
            for (String t : TRANSPORTS) {
                pt.start(t, "");
                torrc.append("ClientTransportPlugin ").append(t).append(" socks5 127.0.0.1:").append(pt.port(t)).append('\n');
            }
            String cc = prefs.getString("country", "");
            if (!cc.isEmpty()) torrc.append("ExitNodes {").append(cc).append("}\nStrictNodes 1\n");
            write(TorService.getDefaultsTorrc(this), "");
            write(TorService.getTorrc(this), torrc.toString());
            ctl = bindTor();

            // Same order as the desktop app: your bridges and the ones that worked last time, then the
            // public lists, then Tor's built-in bridges. Probing first keeps dead bridges out of Tor's way.
            List<String> mine = Bridges.clean(prefs.getString("bridges", "") + "\n" + prefs.getString("lastGood", ""));
            List<String> builtin = Bridges.clean(asset("builtin.txt"));
            String[][] tiers = {{"your bridges"}, {"public lists"}, {"built-in obfs4"}, {"Snowflake"}};
            for (String[] tier : tiers) {
                if (!running) return;
                String name = tier[0];
                List<String> lines = new ArrayList<>();
                boolean probed = true;
                switch (name) {
                    case "your bridges":
                        if (mine.isEmpty()) continue;
                        set("Testing your bridges…");
                        lines = Bridges.fastest(mine, Collections.emptyMap(), 15);
                        for (String l : mine) if (Bridges.target(l) == null) lines.add(l); // snowflake/meek can't be probed
                        break;
                    case "public lists":
                        set("Fetching fresh bridges…");
                        Map<String, Integer> pub = Bridges.fetchPublic(GommageVpn::note);
                        for (String l : Bridges.clean(asset("bridges.txt"))) pub.putIfAbsent(l, 1);
                        set("Testing " + pub.size() + " bridges…");
                        lines = Bridges.fastest(new ArrayList<>(pub.keySet()), pub, 15);
                        break;
                    case "built-in obfs4":
                        for (String l : builtin) if (l.startsWith("obfs4")) lines.add(l);
                        probed = false;
                        break;
                    default:
                        for (String l : builtin) if (l.startsWith("snowflake")) lines.add(l);
                        probed = false;
                }
                note(name + ": " + lines.size() + " bridges");
                if (lines.isEmpty()) continue;
                if (tryBridges(name, lines, name.equals("Snowflake") ? 180 : 100)) {
                    if (probed) prefs.edit().putString("lastGood", String.join("\n", lines)).apply();
                    startTunnel();
                    since = System.currentTimeMillis();
                    connected = true;
                    set("Connected via " + name);
                    return;
                }
            }
            if (running) fail("Couldn't reach Tor. Add bridges you got from a friend or @GetBridgesBot and try again.");
        } catch (Exception e) {
            if (running) fail("Error: " + e.getMessage());
        }
    }

    /** Hands Tor this set of bridges and waits for it to finish bootstrapping. */
    private boolean tryBridges(String name, List<String> lines, int seconds) throws Exception {
        List<String> conf = new ArrayList<>(Collections.singletonList("UseBridges 1"));
        for (String l : lines) conf.add("Bridge " + l);
        conf.add("DisableNetwork 0");
        ctl.setConf(conf);
        Pattern progress = Pattern.compile("PROGRESS=(\\d+)");
        for (long end = System.currentTimeMillis() + seconds * 1000L; running && System.currentTimeMillis() < end; ) {
            Matcher m = progress.matcher(ctl.getInfo("status/bootstrap-phase"));
            int pct = m.find() ? Integer.parseInt(m.group(1)) : 0;
            if (pct >= 100) return true;
            set("Connecting via " + name + "… " + pct + "%");
            Thread.sleep(1000);
        }
        if (running) ctl.setConf(Collections.singletonList("DisableNetwork 1"));
        note(name + ": no connection in " + seconds + " s");
        return false;
    }

    private TorControlConnection bindTor() throws Exception {
        TorService[] svc = new TorService[1];
        CountDownLatch bound = new CountDownLatch(1);
        torConn = new ServiceConnection() {
            public void onServiceConnected(ComponentName n, IBinder b) {
                svc[0] = ((TorService.LocalBinder) b).getService();
                bound.countDown();
            }

            public void onServiceDisconnected(ComponentName n) {
                if (running) fail("Tor stopped unexpectedly");
            }
        };
        if (!bindService(new Intent(this, TorService.class), torConn, BIND_AUTO_CREATE))
            throw new IllegalStateException("can't start Tor");
        if (!bound.await(30, TimeUnit.SECONDS)) throw new IllegalStateException("Tor didn't start");
        for (int i = 0; i < 120; i++) {
            TorControlConnection c = svc[0].getTorControlConnection();
            if (c != null) return c;
            Thread.sleep(500);
        }
        throw new IllegalStateException("Tor control port didn't open");
    }

    /** Every app's traffic -> tun -> hev-socks5-tunnel -> Tor's SOCKS port. DNS is mapped to names Tor resolves. */
    private void startTunnel() throws Exception {
        Builder b = new Builder()
                .setSession("Gommage")
                .setMtu(8500)
                .addAddress("198.18.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addAddress("fc00::1", 128)
                .addRoute("::", 0) // IPv6 goes into the tunnel too, so it can't leak around Tor
                .addDnsServer("198.18.0.2")
                .addDisallowedApplication(getPackageName()); // Tor itself must reach the bridges directly
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
        tun = b.establish();
        if (tun == null) throw new IllegalStateException("VPN permission was withdrawn");
        File conf = new File(getCacheDir(), "tunnel.yml");
        write(conf, "misc:\n  log-level: warn\n  task-stack-size: 81920\n"
                + "tunnel:\n  mtu: 8500\n  ipv4: 198.18.0.1\n  ipv6: 'fc00::1'\n"
                + "socks5:\n  port: " + SOCKS + "\n  address: 127.0.0.1\n  udp: 'udp'\n"
                + "mapdns:\n  address: 198.18.0.2\n  port: 53\n  network: 240.0.0.0\n  netmask: 240.0.0.0\n  cache-size: 10000\n");
        TProxyService.TProxyStartService(conf.getAbsolutePath(), tun.getFd());
    }

    private synchronized void shutdown() {
        if (!running && tun == null && torConn == null) return;
        running = false;
        connected = false;
        if (worker != null) worker.interrupt();
        try {
            if (tun != null) {
                TProxyService.TProxyStopService();
                tun.close();
            }
        } catch (Exception ignored) {
        }
        tun = null;
        if (torConn != null) {
            try {
                unbindService(torConn); // unbinding stops Tor
            } catch (Exception ignored) {
            }
            torConn = null;
        }
        ctl = null;
        if (pt != null) for (String t : TRANSPORTS) pt.stop(t);
        set("Not connected");
    }

    private void fail(String msg) {
        note(msg);
        shutdown();
        failed = true;
        status = msg;
        ping();
        stopSelf();
    }

    private String asset(String name) throws Exception {
        return Bridges.read(getAssets().open(name), 1_000_000);
    }

    static String firstLine(String text, String prefix) {
        for (String l : Bridges.clean(text)) if (l.startsWith(prefix)) return l;
        return "";
    }

    /** key=value pairs of a bridge line. */
    static Map<String, String> params(String line) {
        Map<String, String> out = new java.util.HashMap<>();
        for (String w : line.split(" ")) {
            int i = w.indexOf('=');
            if (i > 0) out.put(w.substring(0, i), w.substring(i + 1));
        }
        return out;
    }

    private static void write(File f, String text) throws Exception {
        try (FileOutputStream o = new FileOutputStream(f)) {
            o.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static void set(String s) {
        status = s;
        note(s);
    }

    static void note(String s) {
        log.add(new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date()) + "  " + s);
        while (log.size() > 200) log.remove(0);
        ping();
    }

    private static void ping() {
        Runnable r = onChange;
        if (r != null) r.run();
    }
}
