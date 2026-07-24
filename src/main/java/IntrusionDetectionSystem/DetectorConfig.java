package IntrusionDetectionSystem;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public final class DetectorConfig {

    private final long windowMillis;
    private final int portScanThreshold;
    private final int hostScanThreshold;
    private final int synFloodThreshold;
    private final int udpFloodThreshold;
    private final int icmpFloodThreshold;
    private final int maximumPacketSize;
    private final long alertCooldownMillis;
    private final Set<Integer> watchedPorts;

    public DetectorConfig(
            long windowMillis,
            int portScanThreshold,
            int hostScanThreshold,
            int synFloodThreshold,
            int udpFloodThreshold,
            int icmpFloodThreshold,
            int maximumPacketSize,
            long alertCooldownMillis,
            Set<Integer> watchedPorts
    ) {
        requirePositive(windowMillis, "windowMillis");
        requirePositive(portScanThreshold, "portScanThreshold");
        requirePositive(hostScanThreshold, "hostScanThreshold");
        requirePositive(synFloodThreshold, "synFloodThreshold");
        requirePositive(udpFloodThreshold, "udpFloodThreshold");
        requirePositive(icmpFloodThreshold, "icmpFloodThreshold");
        requirePositive(maximumPacketSize, "maximumPacketSize");
        if (alertCooldownMillis < 0) {
            throw new IllegalArgumentException("alertCooldownMillis must not be negative");
        }
        if (watchedPorts == null) {
            throw new IllegalArgumentException("watchedPorts must not be null");
        }
        for (Integer port : watchedPorts) {
            if (port == null || port < 1 || port > 65535) {
                throw new IllegalArgumentException("watched ports must be between 1 and 65535");
            }
        }

        this.windowMillis = windowMillis;
        this.portScanThreshold = portScanThreshold;
        this.hostScanThreshold = hostScanThreshold;
        this.synFloodThreshold = synFloodThreshold;
        this.udpFloodThreshold = udpFloodThreshold;
        this.icmpFloodThreshold = icmpFloodThreshold;
        this.maximumPacketSize = maximumPacketSize;
        this.alertCooldownMillis = alertCooldownMillis;
        this.watchedPorts = Collections.unmodifiableSet(new LinkedHashSet<Integer>(watchedPorts));
    }

    public static DetectorConfig defaults() {
        return new DetectorConfig(
                10_000L,
                15,
                20,
                100,
                250,
                100,
                2_000,
                30_000L,
                new LinkedHashSet<Integer>(Arrays.asList(23, 2323, 4444, 5555, 31337))
        );
    }

    public long getWindowMillis() {
        return windowMillis;
    }

    public int getPortScanThreshold() {
        return portScanThreshold;
    }

    public int getHostScanThreshold() {
        return hostScanThreshold;
    }

    public int getSynFloodThreshold() {
        return synFloodThreshold;
    }

    public int getUdpFloodThreshold() {
        return udpFloodThreshold;
    }

    public int getIcmpFloodThreshold() {
        return icmpFloodThreshold;
    }

    public int getMaximumPacketSize() {
        return maximumPacketSize;
    }

    public long getAlertCooldownMillis() {
        return alertCooldownMillis;
    }

    public Set<Integer> getWatchedPorts() {
        return watchedPorts;
    }

    private static void requirePositive(long value, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
