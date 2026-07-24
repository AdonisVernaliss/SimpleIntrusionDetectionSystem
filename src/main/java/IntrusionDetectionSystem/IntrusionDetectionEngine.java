package IntrusionDetectionSystem;

import java.util.List;

public interface IntrusionDetectionEngine {
    List<SecurityAlert> detect(PacketMetadata packet);
}
