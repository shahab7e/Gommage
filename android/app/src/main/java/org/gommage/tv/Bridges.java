package org.gommage.tv;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Bridge lists, probing and ranking: a port of the desktop app's gommage.py logic. */
final class Bridges {
    // Same auto-updated GitHub collections as the desktop app, with the jsDelivr mirror as fallback
    static final String[][] SOURCES = {
            {"Delta-Kronecker/Tor-Bridges-Collector", "bridge/obfs4_tested.txt"},
            {"Delta-Kronecker/Tor-Bridges-Collector", "bridge/webtunnel_tested.txt"},
            {"scriptzteam/Tor-Bridges-Collector", "bridges-webtunnel"},
    };
    // Strict shape, so a tampered list can't inject anything but obfs4/webtunnel lines
    static final Pattern VALID = Pattern.compile(
            "obfs4 \\d{1,3}(?:\\.\\d{1,3}){3}:\\d{1,5} [0-9A-F]{40} cert=[A-Za-z0-9+/]{60,90} iat-mode=[012]"
                    + "|webtunnel \\[[0-9a-fA-F:]+\\]:\\d{1,5} [0-9A-F]{40} url=https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~/-]*)? ver=[0-9.]+");
    private static final Pattern FP = Pattern.compile("\\b([0-9A-F]{40})\\b");

    /** Lines with or without a leading "Bridge ", minus blanks, comments and duplicates. */
    static List<String> clean(String text) {
        List<String> out = new ArrayList<>();
        for (String l : text.split("\n")) {
            l = l.trim().replaceFirst("(?i)^bridge\\s+", "");
            if (!l.isEmpty() && !l.startsWith("#") && !out.contains(l)) out.add(l);
        }
        return out;
    }

    static String fingerprint(String line) {
        Matcher m = FP.matcher(line);
        return m.find() ? m.group(1) : line;
    }

    /** {host, port, "tls"|""} that lyrebird dials, or null when it can't be probed (snowflake, meek). */
    static String[] target(String line) {
        Matcher m = Pattern.compile("url=https?://([^/\\s:]+)").matcher(line);
        if (line.startsWith("webtunnel") && m.find()) return new String[]{m.group(1), "443", "tls"};
        m = Pattern.compile("^\\S+\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)").matcher(line);
        if (m.find() && !m.group(1).startsWith("192.0.2.")) return new String[]{m.group(1), m.group(2), ""};
        return null;
    }

    /** Latency in ms, -1 if unreachable, null if not probeable. */
    static Long probe(String line, int timeoutMs) {
        String[] t = target(line);
        if (t == null) return null;
        long t0 = System.nanoTime();
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(t[0], Integer.parseInt(t[1])), timeoutMs);
            if (!t[2].isEmpty()) { // webtunnel: a real cert check catches DNS poisoning and wrong-cert bridges
                s.setSoTimeout(timeoutMs);
                try (SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                        .createSocket(s, t[0], 443, false)) {
                    tls.startHandshake();
                    if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(t[0], tls.getSession())) return -1L;
                }
            }
            return (System.nanoTime() - t0) / 1_000_000;
        } catch (Exception e) {
            return -1L;
        }
    }

    /** Reachable bridges, fastest first, one per fingerprint, up to limit. Ones listed by several sources rank higher. */
    static List<String> fastest(List<String> lines, Map<String, Integer> votes, int limit) {
        ExecutorService ex = Executors.newFixedThreadPool(64);
        Map<String, Future<Long>> jobs = new LinkedHashMap<>();
        for (String l : lines) jobs.put(l, ex.submit(() -> probe(l, 6000)));
        Map<String, Double> score = new HashMap<>();
        for (Map.Entry<String, Future<Long>> j : jobs.entrySet()) {
            try {
                Long ms = j.getValue().get();
                if (ms != null && ms >= 0) score.put(j.getKey(), ms / (double) votes.getOrDefault(j.getKey(), 1));
            } catch (Exception ignored) {
            }
        }
        ex.shutdown();
        List<String> alive = new ArrayList<>(score.keySet());
        alive.sort(Comparator.comparingDouble(score::get));
        Set<String> seen = new HashSet<>();
        List<String> out = new ArrayList<>();
        for (String l : alive)
            if (out.size() < limit && seen.add(fingerprint(l))) out.add(l);
        return out;
    }

    /** {line: number of lists carrying it} from the public lists; only well-formed lines. */
    static Map<String, Integer> fetchPublic(Consumer<String> log) {
        Map<String, Integer> found = new LinkedHashMap<>();
        for (String[] src : SOURCES) {
            for (String url : new String[]{
                    "https://raw.githubusercontent.com/" + src[0] + "/main/" + src[1],
                    "https://cdn.jsdelivr.net/gh/" + src[0] + "@main/" + src[1]}) {
                try {
                    int n = 0;
                    for (String l : clean(get(url))) {
                        if (!VALID.matcher(l).matches()) continue;
                        found.merge(l, 1, Integer::sum);
                        n++;
                    }
                    log.accept("public list " + src[1] + ": " + n + " bridges");
                    break;
                } catch (Exception e) {
                    log.accept("public list " + src[1] + ": " + e.getMessage());
                }
            }
        }
        return found;
    }

    static String get(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(15000);
        c.setReadTimeout(20000);
        c.setRequestProperty("User-Agent", "Mozilla/5.0");
        try (InputStream in = c.getInputStream()) {
            return read(in, 2_000_000);
        } finally {
            c.disconnect();
        }
    }

    static String read(InputStream in, int max) throws Exception {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        for (int n; b.size() < max && (n = in.read(buf)) > 0; ) b.write(buf, 0, n);
        return b.toString("UTF-8");
    }
}
