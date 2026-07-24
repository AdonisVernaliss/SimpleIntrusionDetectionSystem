package IntrusionDetectionSystem;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimpleIntrusionDetectionEngineTest {

    @Test
    void detectsTcpFlagSignaturesAndCooldown() {
        SimpleIntrusionDetectionEngine engine = new SimpleIntrusionDetectionEngine(config(
                50, 50, 50, 50, 50
        ));

        List<SecurityAlert> first = engine.detect(tcp(1_000L, 80, false, false, false, false, false));
        List<SecurityAlert> repeated = engine.detect(tcp(
                1_001L, 80, false, false, false, false, false
        ));
        List<SecurityAlert> xmas = engine.detect(tcp(
                1_002L, 80, false, false, true, true, true
        ));
        List<SecurityAlert> synFin = engine.detect(tcp(
                1_003L, 80, true, false, true, false, false
        ));

        assertTrue(contains(first, SecurityAlert.Type.TCP_NULL_SCAN));
        assertFalse(contains(repeated, SecurityAlert.Type.TCP_NULL_SCAN));
        assertTrue(contains(xmas, SecurityAlert.Type.TCP_XMAS_SCAN));
        assertTrue(contains(synFin, SecurityAlert.Type.TCP_SYN_FIN));
    }

    @Test
    void detectsPortScanAndSynFlood() {
        SimpleIntrusionDetectionEngine engine = new SimpleIntrusionDetectionEngine(config(
                3, 50, 3, 50, 50
        ));

        engine.detect(tcp(1_000L, 80, true, false, false, false, false));
        engine.detect(tcp(1_001L, 81, true, false, false, false, false));
        List<SecurityAlert> alerts = engine.detect(tcp(
                1_002L, 82, true, false, false, false, false
        ));

        assertTrue(contains(alerts, SecurityAlert.Type.PORT_SCAN));
        assertTrue(contains(alerts, SecurityAlert.Type.SYN_FLOOD));
    }

    @Test
    void detectsHostScanAndFloodProtocols() {
        SimpleIntrusionDetectionEngine hostEngine = new SimpleIntrusionDetectionEngine(config(
                50, 3, 50, 50, 50
        ));
        hostEngine.detect(tcpTo(1_000L, "198.51.100.1"));
        hostEngine.detect(tcpTo(1_001L, "198.51.100.2"));
        List<SecurityAlert> hostAlerts = hostEngine.detect(tcpTo(
                1_002L, "198.51.100.3"
        ));

        SimpleIntrusionDetectionEngine floodEngine = new SimpleIntrusionDetectionEngine(config(
                50, 50, 50, 3, 3
        ));
        floodEngine.detect(packet(1_000L, PacketMetadata.Protocol.UDP, 53));
        floodEngine.detect(packet(1_001L, PacketMetadata.Protocol.UDP, 53));
        List<SecurityAlert> udpAlerts = floodEngine.detect(packet(
                1_002L, PacketMetadata.Protocol.UDP, 53
        ));
        floodEngine.detect(packet(2_000L, PacketMetadata.Protocol.ICMP, null));
        floodEngine.detect(packet(2_001L, PacketMetadata.Protocol.ICMP, null));
        List<SecurityAlert> icmpAlerts = floodEngine.detect(packet(
                2_002L, PacketMetadata.Protocol.ICMP, null
        ));

        assertTrue(contains(hostAlerts, SecurityAlert.Type.HOST_SCAN));
        assertTrue(contains(udpAlerts, SecurityAlert.Type.UDP_FLOOD));
        assertTrue(contains(icmpAlerts, SecurityAlert.Type.ICMP_FLOOD));
    }

    @Test
    void detectsWatchedPortAndOversizedPacket() {
        DetectorConfig config = new DetectorConfig(
                10_000L,
                50,
                50,
                50,
                50,
                50,
                1_500,
                30_000L,
                Collections.singleton(4444)
        );
        SimpleIntrusionDetectionEngine engine = new SimpleIntrusionDetectionEngine(config);
        PacketMetadata metadata = new PacketMetadata(
                1_000L,
                2_048,
                "192.0.2.1",
                "198.51.100.2",
                12345,
                4444,
                PacketMetadata.Protocol.TCP,
                true,
                false,
                false,
                true,
                true,
                false,
                false,
                false,
                false
        );

        List<SecurityAlert> alerts = engine.detect(metadata);

        assertTrue(contains(alerts, SecurityAlert.Type.WATCHED_PORT));
        assertTrue(contains(alerts, SecurityAlert.Type.OVERSIZED_PACKET));
    }

    @Test
    void expiresOldObservationsOutsideSlidingWindow() {
        SimpleIntrusionDetectionEngine engine = new SimpleIntrusionDetectionEngine(config(
                3, 50, 50, 50, 50
        ));

        engine.detect(tcp(1_000L, 80, true, false, false, false, false));
        engine.detect(tcp(2_000L, 81, true, false, false, false, false));
        List<SecurityAlert> alerts = engine.detect(tcp(
                20_000L, 82, true, false, false, false, false
        ));

        assertFalse(contains(alerts, SecurityAlert.Type.PORT_SCAN));
    }

    private static DetectorConfig config(
            int portScan,
            int hostScan,
            int syn,
            int udp,
            int icmp
    ) {
        return new DetectorConfig(
                10_000L,
                portScan,
                hostScan,
                syn,
                udp,
                icmp,
                2_000,
                30_000L,
                Collections.<Integer>emptySet()
        );
    }

    private static PacketMetadata tcp(
            long timestamp,
            int destinationPort,
            boolean syn,
            boolean ack,
            boolean fin,
            boolean psh,
            boolean urg
    ) {
        return new PacketMetadata(
                timestamp,
                64,
                "192.0.2.1",
                "198.51.100.2",
                49152,
                destinationPort,
                PacketMetadata.Protocol.TCP,
                true,
                false,
                false,
                syn,
                ack,
                fin,
                false,
                psh,
                urg
        );
    }

    private static PacketMetadata tcpTo(long timestamp, String destination) {
        return new PacketMetadata(
                timestamp,
                64,
                "192.0.2.1",
                destination,
                49152,
                443,
                PacketMetadata.Protocol.TCP,
                true,
                false,
                false,
                true,
                false,
                false,
                false,
                false,
                false
        );
    }

    private static PacketMetadata packet(
            long timestamp,
            PacketMetadata.Protocol protocol,
            Integer destinationPort
    ) {
        return new PacketMetadata(
                timestamp,
                64,
                "192.0.2.1",
                "198.51.100.2",
                destinationPort == null ? null : 49152,
                destinationPort,
                protocol,
                true,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                false
        );
    }

    private static boolean contains(
            List<SecurityAlert> alerts,
            SecurityAlert.Type type
    ) {
        for (SecurityAlert alert : alerts) {
            if (alert.getType() == type) {
                return true;
            }
        }
        return false;
    }
}
