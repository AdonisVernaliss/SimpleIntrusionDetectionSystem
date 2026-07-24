package IntrusionDetectionSystem;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CommandLineOptionsTest {

    @Test
    void parsesOfflineAndDetectionOptions() {
        CommandLineOptions options = CommandLineOptions.parse(new String[]{
                "--read", "sample.pcap",
                "--count", "25",
                "--json",
                "--window-seconds", "5",
                "--watch-ports", "22,8443"
        });

        assertEquals("sample.pcap", options.getInputFile());
        assertEquals(25L, options.getPacketLimit());
        assertTrue(options.isJson());
        assertEquals(5_000L, options.detectorConfig().getWindowMillis());
        assertTrue(options.detectorConfig().getWatchedPorts().contains(22));
        assertTrue(options.detectorConfig().getWatchedPorts().contains(8443));
        assertFalse(options.detectorConfig().getWatchedPorts().contains(23));
    }

    @Test
    void supportsDisablingWatchedPorts() {
        CommandLineOptions options = CommandLineOptions.parse(new String[]{
                "--watch-ports", "none",
                "--filter", "none"
        });

        assertTrue(options.detectorConfig().getWatchedPorts().isEmpty());
        assertEquals(null, options.getFilter());
    }

    @Test
    void rejectsConflictingSourcesAndBadNumbers() {
        assertThrows(
                IllegalArgumentException.class,
                () -> CommandLineOptions.parse(new String[]{
                        "--interface", "eth0", "--read", "sample.pcap"
                })
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> CommandLineOptions.parse(new String[]{"--count", "0"})
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> CommandLineOptions.parse(new String[]{"--watch-ports", "70000"})
        );
    }
}
