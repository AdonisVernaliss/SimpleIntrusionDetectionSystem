package IntrusionDetectionSystem;

import org.pcap4j.packet.Packet;

public interface PacketAnalyzer {
    void analyze(Packet packet);
}
