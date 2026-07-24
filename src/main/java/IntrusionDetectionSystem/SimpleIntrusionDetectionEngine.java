package IntrusionDetectionSystem;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public final class SimpleIntrusionDetectionEngine implements IntrusionDetectionEngine {

    private static final String KEY_SEPARATOR = "\u0000";
    private static final int CLEANUP_INTERVAL = 2_048;

    private final DetectorConfig config;
    private final Map<String, RateWindow> synWindows = new HashMap<String, RateWindow>();
    private final Map<String, RateWindow> udpWindows = new HashMap<String, RateWindow>();
    private final Map<String, RateWindow> icmpWindows = new HashMap<String, RateWindow>();
    private final Map<String, UniqueWindow> portScanWindows = new HashMap<String, UniqueWindow>();
    private final Map<String, UniqueWindow> hostScanWindows = new HashMap<String, UniqueWindow>();
    private final Map<String, Long> lastAlertTimes = new HashMap<String, Long>();
    private long processedPackets;

    public SimpleIntrusionDetectionEngine() {
        this(DetectorConfig.defaults());
    }

    public SimpleIntrusionDetectionEngine(DetectorConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config must not be null");
        }
        this.config = config;
    }

    @Override
    public List<SecurityAlert> detect(PacketMetadata packet) {
        if (packet == null) {
            throw new IllegalArgumentException("packet must not be null");
        }

        List<SecurityAlert> alerts = new ArrayList<SecurityAlert>();
        long now = packet.getTimestampMillis();

        detectPacketSize(packet, alerts, now);
        detectWatchedPort(packet, alerts, now);

        if (packet.getProtocol() == PacketMetadata.Protocol.TCP) {
            detectTcpFlags(packet, alerts, now);
            detectTcpRates(packet, alerts, now);
        } else if (packet.getProtocol() == PacketMetadata.Protocol.UDP) {
            detectFlood(
                    packet,
                    alerts,
                    now,
                    udpWindows,
                    config.getUdpFloodThreshold(),
                    SecurityAlert.Type.UDP_FLOOD,
                    SecurityAlert.Severity.HIGH,
                    "UDP packet rate exceeded "
            );
        } else if (packet.getProtocol() == PacketMetadata.Protocol.ICMP) {
            detectFlood(
                    packet,
                    alerts,
                    now,
                    icmpWindows,
                    config.getIcmpFloodThreshold(),
                    SecurityAlert.Type.ICMP_FLOOD,
                    SecurityAlert.Severity.HIGH,
                    "ICMP packet rate exceeded "
            );
        }

        processedPackets++;
        if (processedPackets % CLEANUP_INTERVAL == 0) {
            cleanup(now);
        }
        return alerts;
    }

    private void detectPacketSize(PacketMetadata packet, List<SecurityAlert> alerts, long now) {
        if (packet.getPacketLength() <= config.getMaximumPacketSize()) {
            return;
        }
        String cooldownKey = SecurityAlert.Type.OVERSIZED_PACKET + KEY_SEPARATOR
                + key(packet.getSourceAddress(), packet.getDestinationAddress());
        if (canAlert(cooldownKey, now)) {
            alerts.add(alert(
                    packet,
                    SecurityAlert.Severity.MEDIUM,
                    SecurityAlert.Type.OVERSIZED_PACKET,
                    "Packet length " + packet.getPacketLength()
                            + " bytes exceeded configured maximum "
                            + config.getMaximumPacketSize() + " bytes"
            ));
        }
    }

    private void detectWatchedPort(PacketMetadata packet, List<SecurityAlert> alerts, long now) {
        Integer destinationPort = packet.getDestinationPort();
        if (destinationPort == null || !config.getWatchedPorts().contains(destinationPort)) {
            return;
        }
        String cooldownKey = SecurityAlert.Type.WATCHED_PORT + KEY_SEPARATOR
                + key(packet.getSourceAddress(), packet.getDestinationAddress())
                + KEY_SEPARATOR + destinationPort;
        if (canAlert(cooldownKey, now)) {
            alerts.add(alert(
                    packet,
                    SecurityAlert.Severity.MEDIUM,
                    SecurityAlert.Type.WATCHED_PORT,
                    "Traffic targeted watched destination port " + destinationPort
            ));
        }
    }

    private void detectTcpFlags(PacketMetadata packet, List<SecurityAlert> alerts, long now) {
        if (!packet.hasAnyTcpFlag()) {
            addFlagAlert(
                    packet,
                    alerts,
                    now,
                    SecurityAlert.Type.TCP_NULL_SCAN,
                    "TCP packet has no control flags set"
            );
        }
        if (packet.isTcpFin() && packet.isTcpPsh() && packet.isTcpUrg()) {
            addFlagAlert(
                    packet,
                    alerts,
                    now,
                    SecurityAlert.Type.TCP_XMAS_SCAN,
                    "TCP FIN, PSH, and URG flags are set together"
            );
        }
        if (packet.isTcpSyn() && packet.isTcpFin()) {
            addFlagAlert(
                    packet,
                    alerts,
                    now,
                    SecurityAlert.Type.TCP_SYN_FIN,
                    "TCP SYN and FIN flags are set together"
            );
        }
    }

    private void addFlagAlert(
            PacketMetadata packet,
            List<SecurityAlert> alerts,
            long now,
            SecurityAlert.Type type,
            String message
    ) {
        String cooldownKey = type + KEY_SEPARATOR
                + key(packet.getSourceAddress(), packet.getDestinationAddress());
        if (canAlert(cooldownKey, now)) {
            alerts.add(alert(packet, SecurityAlert.Severity.HIGH, type, message));
        }
    }

    private void detectTcpRates(PacketMetadata packet, List<SecurityAlert> alerts, long now) {
        if (!packet.isTcpSyn() || packet.isTcpAck()) {
            return;
        }
        String source = packet.getSourceAddress();
        String destination = packet.getDestinationAddress();
        if (source == null || destination == null) {
            return;
        }

        String pairKey = key(source, destination);
        int synCount = rateCount(synWindows, pairKey, now);
        if (synCount >= config.getSynFloodThreshold()) {
            String cooldownKey = SecurityAlert.Type.SYN_FLOOD + KEY_SEPARATOR + pairKey;
            if (canAlert(cooldownKey, now)) {
                alerts.add(alert(
                        packet,
                        SecurityAlert.Severity.CRITICAL,
                        SecurityAlert.Type.SYN_FLOOD,
                        "TCP SYN packet rate reached " + synCount + " in "
                                + seconds(config.getWindowMillis()) + " seconds"
                ));
            }
        }

        if (packet.getDestinationPort() != null) {
            UniqueWindow portWindow = getUniqueWindow(portScanWindows, pairKey);
            int uniquePorts = portWindow.add(
                    Integer.toString(packet.getDestinationPort()),
                    now,
                    config.getWindowMillis()
            );
            if (uniquePorts >= config.getPortScanThreshold()) {
                String cooldownKey = SecurityAlert.Type.PORT_SCAN + KEY_SEPARATOR + pairKey;
                if (canAlert(cooldownKey, now)) {
                    alerts.add(alert(
                            packet,
                            SecurityAlert.Severity.HIGH,
                            SecurityAlert.Type.PORT_SCAN,
                            "TCP SYN traffic reached " + uniquePorts
                                    + " unique destination ports in "
                                    + seconds(config.getWindowMillis()) + " seconds"
                    ));
                }
            }
        }

        UniqueWindow hostWindow = getUniqueWindow(hostScanWindows, source);
        int uniqueHosts = hostWindow.add(destination, now, config.getWindowMillis());
        if (uniqueHosts >= config.getHostScanThreshold()) {
            String cooldownKey = SecurityAlert.Type.HOST_SCAN + KEY_SEPARATOR + source;
            if (canAlert(cooldownKey, now)) {
                alerts.add(alert(
                        packet,
                        SecurityAlert.Severity.HIGH,
                        SecurityAlert.Type.HOST_SCAN,
                        "TCP SYN traffic reached " + uniqueHosts
                                + " unique destination hosts in "
                                + seconds(config.getWindowMillis()) + " seconds"
                ));
            }
        }
    }

    private void detectFlood(
            PacketMetadata packet,
            List<SecurityAlert> alerts,
            long now,
            Map<String, RateWindow> windows,
            int threshold,
            SecurityAlert.Type type,
            SecurityAlert.Severity severity,
            String messagePrefix
    ) {
        String source = packet.getSourceAddress();
        String destination = packet.getDestinationAddress();
        if (source == null || destination == null) {
            return;
        }
        String pairKey = key(source, destination);
        int count = rateCount(windows, pairKey, now);
        if (count >= threshold) {
            String cooldownKey = type + KEY_SEPARATOR + pairKey;
            if (canAlert(cooldownKey, now)) {
                alerts.add(alert(
                        packet,
                        severity,
                        type,
                        messagePrefix + count + " in "
                                + seconds(config.getWindowMillis()) + " seconds"
                ));
            }
        }
    }

    private int rateCount(Map<String, RateWindow> windows, String key, long now) {
        RateWindow window = windows.get(key);
        if (window == null) {
            window = new RateWindow();
            windows.put(key, window);
        }
        return window.add(now, config.getWindowMillis());
    }

    private UniqueWindow getUniqueWindow(Map<String, UniqueWindow> windows, String key) {
        UniqueWindow window = windows.get(key);
        if (window == null) {
            window = new UniqueWindow();
            windows.put(key, window);
        }
        return window;
    }

    private boolean canAlert(String cooldownKey, long now) {
        Long lastAlert = lastAlertTimes.get(cooldownKey);
        if (lastAlert != null && now >= lastAlert
                && now - lastAlert < config.getAlertCooldownMillis()) {
            return false;
        }
        lastAlertTimes.put(cooldownKey, now);
        return true;
    }

    private SecurityAlert alert(
            PacketMetadata packet,
            SecurityAlert.Severity severity,
            SecurityAlert.Type type,
            String message
    ) {
        return new SecurityAlert(
                packet.getTimestampMillis(),
                severity,
                type,
                packet.getSourceAddress(),
                packet.getDestinationAddress(),
                packet.getSourcePort(),
                packet.getDestinationPort(),
                message
        );
    }

    private void cleanup(long now) {
        long cutoff = now - Math.max(config.getWindowMillis() * 2L, 60_000L);
        cleanupTimedMap(synWindows, cutoff);
        cleanupTimedMap(udpWindows, cutoff);
        cleanupTimedMap(icmpWindows, cutoff);
        cleanupTimedMap(portScanWindows, cutoff);
        cleanupTimedMap(hostScanWindows, cutoff);

        Iterator<Map.Entry<String, Long>> alertIterator = lastAlertTimes.entrySet().iterator();
        while (alertIterator.hasNext()) {
            Map.Entry<String, Long> entry = alertIterator.next();
            if (entry.getValue() < cutoff) {
                alertIterator.remove();
            }
        }
    }

    private static void cleanupTimedMap(
            Map<String, ? extends TimedWindow> windows,
            long cutoff
    ) {
        Iterator<? extends Map.Entry<String, ? extends TimedWindow>> iterator =
                windows.entrySet().iterator();
        while (iterator.hasNext()) {
            if (iterator.next().getValue().getLastSeen() < cutoff) {
                iterator.remove();
            }
        }
    }

    private static String key(String first, String second) {
        return String.valueOf(first) + KEY_SEPARATOR + String.valueOf(second);
    }

    private static long seconds(long millis) {
        return Math.max(1L, millis / 1_000L);
    }

    private interface TimedWindow {
        long getLastSeen();
    }

    private static final class RateWindow implements TimedWindow {
        private final Deque<Long> timestamps = new ArrayDeque<Long>();
        private long lastSeen;

        private int add(long timestamp, long windowMillis) {
            prune(timestamp - windowMillis);
            timestamps.addLast(timestamp);
            lastSeen = timestamp;
            return timestamps.size();
        }

        private void prune(long cutoff) {
            while (!timestamps.isEmpty() && timestamps.peekFirst() < cutoff) {
                timestamps.removeFirst();
            }
        }

        @Override
        public long getLastSeen() {
            return lastSeen;
        }
    }

    private static final class UniqueWindow implements TimedWindow {
        private final Deque<Observation> observations = new ArrayDeque<Observation>();
        private final Map<String, Integer> counts = new HashMap<String, Integer>();
        private long lastSeen;

        private int add(String value, long timestamp, long windowMillis) {
            prune(timestamp - windowMillis);
            observations.addLast(new Observation(timestamp, value));
            Integer count = counts.get(value);
            counts.put(value, count == null ? 1 : count + 1);
            lastSeen = timestamp;
            return counts.size();
        }

        private void prune(long cutoff) {
            while (!observations.isEmpty() && observations.peekFirst().timestamp < cutoff) {
                Observation observation = observations.removeFirst();
                int count = counts.get(observation.value);
                if (count <= 1) {
                    counts.remove(observation.value);
                } else {
                    counts.put(observation.value, count - 1);
                }
            }
        }

        @Override
        public long getLastSeen() {
            return lastSeen;
        }
    }

    private static final class Observation {
        private final long timestamp;
        private final String value;

        private Observation(long timestamp, String value) {
            this.timestamp = timestamp;
            this.value = value;
        }
    }
}
