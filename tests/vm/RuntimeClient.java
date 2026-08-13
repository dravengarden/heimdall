import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

public final class RuntimeClient {
    private RuntimeClient() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("usage: RuntimeClient tcp|udp4|udp6");
        if (args[0].equals("tcp")) tcp();
        else udp(args[0]);
        System.out.println("java-" + args[0] + "-ok");
    }

    private static void tcp() throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("fixture.test", 18080), 5000);
            socket.setSoTimeout(5000);
            socket.getOutputStream().write(
                "GET / HTTP/1.0\r\nHost: fixture.test\r\n\r\n".getBytes(StandardCharsets.US_ASCII)
            );
            try (InputStream input = socket.getInputStream()) {
                String response = new String(input.readAllBytes(), StandardCharsets.US_ASCII);
                if (!response.endsWith("fixture-v4")) {
                    throw new IllegalStateException("unexpected TCP response: " + response);
                }
            }
        }
    }

    private static void udp(String mode) throws Exception {
        boolean ipv6 = mode.equals("udp6");
        if (!ipv6 && !mode.equals("udp4")) throw new IllegalArgumentException("unknown mode: " + mode);
        String host = ipv6 ? "::1" : "127.0.0.1";
        int port = ipv6 ? 18083 : 18082;
        String expected = (ipv6 ? "udp-v6:" : "udp-v4:") + "runtime-java";
        try (DatagramChannel channel = DatagramChannel.open(
                ipv6 ? StandardProtocolFamily.INET6 : StandardProtocolFamily.INET)) {
            InetSocketAddress peer = new InetSocketAddress(InetAddress.getByName(host), port);
            channel.connect(peer);
            channel.write(ByteBuffer.wrap("runtime-java".getBytes(StandardCharsets.US_ASCII)));
            channel.configureBlocking(false);
            ByteBuffer response = ByteBuffer.allocate(128);
            Instant deadline = Instant.now().plus(Duration.ofSeconds(5));
            while (channel.read(response) == 0) {
                if (Instant.now().isAfter(deadline)) throw new IllegalStateException("UDP timeout");
                Thread.sleep(10);
            }
            response.flip();
            String actual = StandardCharsets.US_ASCII.decode(response).toString();
            if (!actual.equals(expected) || !channel.getRemoteAddress().equals(peer)) {
                throw new IllegalStateException("unexpected UDP response: " + actual);
            }
        }
    }
}
