package IntrusionDetectionSystem;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityAlertTest {

    @Test
    void createsValidEscapedJsonFields() {
        SecurityAlert alert = new SecurityAlert(
                0L,
                SecurityAlert.Severity.HIGH,
                SecurityAlert.Type.PORT_SCAN,
                "2001:db8::1",
                "2001:db8::2",
                12345,
                443,
                "line one\n\"quoted\""
        );

        String json = alert.toJson();

        assertTrue(json.startsWith("{\"timestamp\":\"1970-01-01T00:00:00Z\""));
        assertTrue(json.contains("\"source\":\"2001:db8::1\""));
        assertTrue(json.contains("\"message\":\"line one\\n\\\"quoted\\\"\""));
    }
}
