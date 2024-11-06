import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Random;

public class Cliente {

    private PublicKey publicKeyServidor;
    private BigInteger p, g, gy, y;
    private BigInteger sharedSecret; // Llave maestra

    public Cliente() {
        try {
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get("publicKeyServidor.key"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKeyServidor = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] cifrarAES(byte[] data, SecretKey aesKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        return cipher.doFinal(data);
    }

    private byte[] generarHMAC(byte[] data, SecretKey hmacKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(hmacKey);
        return mac.doFinal(data);
    }

    public void iniciarCliente() {
        try (Socket socket = new Socket("localhost", 1234)) {
            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);

            salida.println("SECINIT");

            int reto = new Random().nextInt(10000);
            System.out.println("Reto generado: " + reto);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKeyServidor);
            byte[] retoCifrado = cipher.doFinal(String.valueOf(reto).getBytes());
            salida.println(Base64.getEncoder().encodeToString(retoCifrado));

            int rta = Integer.parseInt(entrada.readLine().trim());
            if (rta == reto) {
                System.out.println("OK RETO");
                salida.println("OK RETO");

                g = new BigInteger(entrada.readLine().trim());
                p = new BigInteger(entrada.readLine().trim());
                BigInteger gx = new BigInteger(entrada.readLine().trim());
                String firmaCifrada = entrada.readLine();

                Signature firma = Signature.getInstance("SHA1withRSA");
                firma.initVerify(publicKeyServidor);
                String datosParaVerificar = p.toString() + ":" + g.toString() + ":" + gx.toString();
                firma.update(datosParaVerificar.getBytes());

                boolean firmaValida = firma.verify(Base64.getDecoder().decode(firmaCifrada));
                if (firmaValida) {
                    System.out.println("OK FIRMA");

                    // Generar valor secreto y calcular gy
                    y = new BigInteger(1024, new Random());
                    gy = g.modPow(y, p);
                    salida.println(gy.toString());

                    sharedSecret = gx.modPow(y, p);

                    MessageDigest digest = MessageDigest.getInstance("SHA-512");
                    byte[] hash = digest.digest(sharedSecret.toByteArray());

                    SecretKey aesKey = new SecretKeySpec(hash, 0, 32, "AES");
                    SecretKey hmacKey = new SecretKeySpec(hash, 32, 32, "HmacSHA384");

                    IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(entrada.readLine()));

                    String userId = "user123";
                    String packageId = "packageABC";

                    byte[] userIdEncrypted = cifrarAES(userId.getBytes(), aesKey, iv);
                    byte[] packageIdEncrypted = cifrarAES(packageId.getBytes(), aesKey, iv);

                    byte[] userIdHMAC = generarHMAC(userId.getBytes(), hmacKey);
                    byte[] packageIdHMAC = generarHMAC(packageId.getBytes(), hmacKey);

                    salida.println(Base64.getEncoder().encodeToString(userIdEncrypted));
                    salida.println(Base64.getEncoder().encodeToString(packageIdEncrypted));
                    salida.println(Base64.getEncoder().encodeToString(userIdHMAC));
                    salida.println(Base64.getEncoder().encodeToString(packageIdHMAC));

                    String respuesta = entrada.readLine();
                    if ("RECIBIDO".equals(respuesta)) {
                        System.out.println("Servidor confirmó la recepción de los datos.");
                    } else {
                        System.out.println("Error en la recepción de los datos por parte del servidor.");
                    }
                } else {
                    System.out.println("ERROR FIRMA");
                }
            } else {
                System.out.println("ERROR RETO");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        new Cliente().iniciarCliente();
    }
}
