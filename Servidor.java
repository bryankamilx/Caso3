import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Servidor {

    private PrivateKey privateKey;

    public Servidor() {
        try {
            // Generar par de claves (solo para esta implementación de ejemplo)
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();

            // Guardar la clave pública en un archivo para que el cliente la pueda usar
            try (FileOutputStream fos = new FileOutputStream("publicKeyServidor.key")) {
                fos.write(pair.getPublic().getEncoded());
            }

            // Guardar la clave privada en un archivo para cargarla después
            try (FileOutputStream fos = new FileOutputStream("privateKeyServidor.key")) {
                fos.write(privateKey.getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void iniciarServidor() {
        try (ServerSocket serverSocket = new ServerSocket(1234)) {
            System.out.println("Servidor iniciado en el puerto 1234. Esperando cliente...");
            cargarLlavePrivada(); // Cargar la clave privada desde el archivo

            try (Socket socket = serverSocket.accept()) {
                System.out.println("Cliente conectado.");
                BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);

                // Paso 3: Recibir "SECINIT" del cliente
                String mensaje = entrada.readLine();
                if ("SECINIT".equals(mensaje)) {
                    System.out.println("SECINIT recibido del cliente.");

                    // Paso 4: Recibir el reto cifrado (R) del cliente
                    String retoCifrado = entrada.readLine();

                    // Descifrar el reto con la clave privada del servidor
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    byte[] retoDescifradoBytes = cipher.doFinal(Base64.getDecoder().decode(retoCifrado));
                    String rta = new String(retoDescifradoBytes);
                    System.out.println("Reto descifrado: " + rta);

                    // Paso 6: Enviar rta al cliente
                    salida.println(rta);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void cargarLlavePrivada() throws Exception {
        // Cargar la clave privada del servidor desde un archivo
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get("privateKeyServidor.key"));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    public static void main(String[] args) {
        new Servidor().iniciarServidor();
    }
}
