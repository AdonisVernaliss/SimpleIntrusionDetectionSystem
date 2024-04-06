package IntrusionDetectionSystem;

import org.pcap4j.packet.Packet;

public class SimplePacketAnalyzer implements PacketAnalyzer {
    @Override
    public void analyze(Packet packet) {
        System.out.println("Analyzed packet: " + packet);
    }
}
