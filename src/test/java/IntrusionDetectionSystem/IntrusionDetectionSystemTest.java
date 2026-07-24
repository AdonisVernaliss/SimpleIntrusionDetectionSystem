package IntrusionDetectionSystem;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IntrusionDetectionSystemTest {

    @Test
    void helpDoesNotInitializePacketCapture() throws Exception {
        ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream errorBytes = new ByteArrayOutputStream();
        PrintStream output = new PrintStream(outputBytes, true, "UTF-8");
        PrintStream error = new PrintStream(errorBytes, true, "UTF-8");

        int exitCode = IntrusionDetectionSystem.run(
                new String[]{"--help"},
                output,
                error
        );

        assertEquals(0, exitCode);
        assertTrue(new String(outputBytes.toByteArray(), StandardCharsets.UTF_8)
                .contains("--list-interfaces"));
        assertEquals("", new String(errorBytes.toByteArray(), StandardCharsets.UTF_8));
    }

    @Test
    void invalidOptionReturnsUsageError() throws Exception {
        ByteArrayOutputStream errorBytes = new ByteArrayOutputStream();

        int exitCode = IntrusionDetectionSystem.run(
                new String[]{"--does-not-exist"},
                new PrintStream(new ByteArrayOutputStream(), true, "UTF-8"),
                new PrintStream(errorBytes, true, "UTF-8")
        );

        assertEquals(2, exitCode);
        assertTrue(new String(errorBytes.toByteArray(), StandardCharsets.UTF_8)
                .contains("unknown option"));
    }
}
