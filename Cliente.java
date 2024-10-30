import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Random;

public class Cliente {

    private PublicKey publicKeyServidor;

    public Cliente() {
        try {
            // Cargar la clave pública del servidor desde un archivo
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get("publicKeyServidor.key"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKeyServidor = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void iniciarCliente() {
        try (Socket socket = new Socket("localhost", 1234)) {
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);

            // Paso 3: Enviar "SECINIT" al servidor para iniciar la sesión
            salida.println("SECINIT");

            // Paso 4: Generar el reto y cifrarlo con la clave pública del servidor
            int reto = new Random().nextInt(10000); // Número aleatorio como reto
            System.out.println("Reto generado: " + reto);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKeyServidor);
            byte[] retoCifrado = cipher.doFinal(String.valueOf(reto).getBytes());

            // Enviar el reto cifrado al servidor
            salida.println(Base64.getEncoder().encodeToString(retoCifrado));

            // Paso 7: Recibir rta del servidor
            String rta = entrada.readLine();
            System.out.println("Rta recibida del servidor: " + rta);

            // Verificar si rta coincide con el reto original
            if (Integer.parseInt(rta) == reto) {
                System.out.println("OK");
            } else {
                System.out.println("ERROR");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Cliente().iniciarCliente();
    }
}
