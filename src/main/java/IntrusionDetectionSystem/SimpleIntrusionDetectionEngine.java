package IntrusionDetectionSystem;

import org.pcap4j.packet.Packet;

public class SimpleIntrusionDetectionEngine implements IntrusionDetectionEngine {
    private static final int SUSPICIOUS_PACKET_LENGTH = 1500;

    @Override
    public void detect(Packet packet) {
        if (packet.length() > SUSPICIOUS_PACKET_LENGTH) {
            System.out.println("Suspicious packet detected: " + packet);
        }
    }
}

