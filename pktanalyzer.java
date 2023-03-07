import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class pktanalyzer {

    public static int ETHER_HEADER_SIZE = 14;

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Specify path to datafile");
            System.out.println("terminating...");
            System.exit(0);
        }
        PaketAnalyzer paketAnalyzer = new PaketAnalyzer(args[0]);
        paketAnalyzer.processEther();
        paketAnalyzer.processIPv4();
        System.out.print(paketAnalyzer.printEther());
        System.out.print(paketAnalyzer.printIP());
        if (paketAnalyzer.getProtocolStr().equals("Unsupported protocol...")) {
            System.out.println("terminating...");
            System.exit(0);
        }
        else if (paketAnalyzer.getProtocol() == 1) {
            paketAnalyzer.processICMP();
            System.out.print(paketAnalyzer.printICMP());
        }
        else if (paketAnalyzer.getProtocol() == 6) {
            paketAnalyzer.processTCP();
            System.out.print(paketAnalyzer.printTCP());
        }
        else if (paketAnalyzer.getProtocol() == 17) {
            paketAnalyzer.processUDP();
            System.out.println(paketAnalyzer.printUPD());
        }
        else {
            System.out.println("terminating...");
            System.exit(0);
        }

    }

    public static void readPacket(String file) throws IOException {
        Path path = Paths.get(file);
        byte[] fileContents = Files.readAllBytes(path);
//        Byte one = fileContents[0];
        StringBuilder result = new StringBuilder();
        for (byte aByte : fileContents) {
            result.append(String.format("%02x", aByte));
        }

        System.out.println(result);
    }
}
