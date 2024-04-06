package IntrusionDetectionSystem;

import org.pcap4j.packet.Packet;

public interface IntrusionDetectionEngine {
    void detect(Packet packet);
}

