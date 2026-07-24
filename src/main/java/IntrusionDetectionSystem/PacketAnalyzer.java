package IntrusionDetectionSystem;

import org.pcap4j.packet.Packet;

public interface PacketAnalyzer {
    PacketMetadata analyze(Packet packet, long timestampMillis);
}
