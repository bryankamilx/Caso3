import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class Servidor {

    private PrivateKey privateKey;
    private BigInteger p, g, gx, x;
    private BigInteger sharedSecret; // Llave maestra

    public Servidor() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            privateKey = pair.getPrivate();

            try (FileOutputStream fos = new FileOutputStream("publicKeyServidor.key")) {
                fos.write(pair.getPublic().getEncoded());
            }

            try (FileOutputStream fos = new FileOutputStream("privateKeyServidor.key")) {
                fos.write(privateKey.getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] descifrarAES(byte[] data, SecretKey aesKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
        return cipher.doFinal(data);
    }

    private boolean verificarHMAC(byte[] data, byte[] hmac, SecretKey hmacKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(hmacKey);
        byte[] calculatedHMAC = mac.doFinal(data);
        return MessageDigest.isEqual(calculatedHMAC, hmac);
    }

    private BigInteger[] generarPGx(String openSslPath) {
        BigInteger p = null;
        BigInteger g = null;
        BigInteger gx = null;
        try {
            Process process = Runtime.getRuntime().exec(openSslPath + " dhparam -text 1024");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder primeHex = new StringBuilder();
            boolean readingPrime = false;

            while ((line = reader.readLine()) != null) {
                if (line.contains("prime:")) {
                    readingPrime = true;
                } else if (line.contains("generator:")) {
                    readingPrime = false;
                    String generatorValue = line.split(":")[1].trim();
                    g = new BigInteger(generatorValue.split(" ")[0]);
                } else if (readingPrime) {
                    primeHex.append(line.trim().replace(":", ""));
                }
            }
            reader.close();
            process.waitFor();

            if (primeHex.length() > 0) {
                p = new BigInteger(primeHex.toString(), 16);
            }

            x = new BigInteger(1024, new Random());
            gx = g.modPow(x, p);
            System.out.println("Valor de G: " + g);
            System.out.println("Valor de P: " + p);
            System.out.println("Valor de G^x: " + gx);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return new BigInteger[]{p, g, gx};
    }

    public void iniciarServidor(String openSslPath) {
        try (ServerSocket serverSocket = new ServerSocket(1234)) {
            System.out.println("Servidor iniciado en el puerto 1234. Esperando cliente...");
            cargarLlavePrivada();

            try (Socket socket = serverSocket.accept()) {
                System.out.println("Cliente conectado.");
                BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);

                String mensaje = entrada.readLine();
                if ("SECINIT".equals(mensaje)) {
                    System.out.println("SECINIT recibido del cliente.");

                    String retoCifrado = entrada.readLine();
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    int reto = Integer.parseInt(new String(cipher.doFinal(Base64.getDecoder().decode(retoCifrado))));
                    salida.println(reto);

                    String respuesta = entrada.readLine();
                    if ("OK RETO".equals(respuesta)) {
                        System.out.println("Reto verificado correctamente.");

                        BigInteger[] valores = generarPGx(openSslPath);
                        p = valores[0];
                        g = valores[1];
                        gx = valores[2];

                        Signature firma = Signature.getInstance("SHA1withRSA");
                        firma.initSign(privateKey);
                        String datosParaFirmar = p.toString() + ":" + g.toString() + ":" + gx.toString();
                        firma.update(datosParaFirmar.getBytes());
                        byte[] firmaBytes = firma.sign();
                        String firmaCifrada = Base64.getEncoder().encodeToString(firmaBytes);

                        salida.println(g.toString());
                        salida.println(p.toString());
                        salida.println(gx.toString());
                        salida.println(firmaCifrada);

                        BigInteger gy = new BigInteger(entrada.readLine().trim());
                        sharedSecret = gy.modPow(x, p);

                        MessageDigest digest = MessageDigest.getInstance("SHA-512");
                        byte[] hash = digest.digest(sharedSecret.toByteArray());

                        SecretKey aesKey = new SecretKeySpec(hash, 0, 32, "AES");
                        SecretKey hmacKey = new SecretKeySpec(hash, 32, 32, "HmacSHA384");

                        byte[] ivBytes = new byte[16];
                        new SecureRandom().nextBytes(ivBytes);
                        IvParameterSpec iv = new IvParameterSpec(ivBytes);
                        salida.println(Base64.getEncoder().encodeToString(ivBytes));

                        byte[] userIdEncrypted = Base64.getDecoder().decode(entrada.readLine());
                        byte[] packageIdEncrypted = Base64.getDecoder().decode(entrada.readLine());
                        byte[] userIdHMAC = Base64.getDecoder().decode(entrada.readLine());
                        byte[] packageIdHMAC = Base64.getDecoder().decode(entrada.readLine());

                        byte[] userId = descifrarAES(userIdEncrypted, aesKey, iv);
                        byte[] packageId = descifrarAES(packageIdEncrypted, aesKey, iv);

                        boolean userIdHMACValid = verificarHMAC(userId, userIdHMAC, hmacKey);
                        boolean packageIdHMACValid = verificarHMAC(packageId, packageIdHMAC, hmacKey);

                        if (userIdHMACValid && packageIdHMACValid) {
                            System.out.println("HMAC verificado correctamente. Datos recibidos con integridad.");
                            salida.println("RECIBIDO");
                        } else {
                            System.out.println("Error en la verificación del HMAC.");
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void cargarLlavePrivada() throws Exception {
        byte[] privateKeyBytes = Files.readAllBytes(Paths.get("privateKeyServidor.key"));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Ingrese la ruta al ejecutable de OpenSSL: ");
        String openSslPath = scanner.nextLine();
        new Servidor().iniciarServidor(openSslPath);
    }
}
