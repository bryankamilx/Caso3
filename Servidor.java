import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Scanner;

public class Servidor {

    // Método para generar y guardar las llaves
    public void generarLlaves() {
        try {
            // Generador de pareja de llaves RSA de 1024 bits
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();

            // Obtén la llave pública y privada
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();

            // Guarda la llave pública en un archivo dentro de la carpeta 'archivos'
            guardarLlaveEnArchivo(publicKey.getEncoded(), "archivos/publicKey.key");

            // Guarda la llave privada en un archivo dentro de la carpeta 'archivos'
            guardarLlaveEnArchivo(privateKey.getEncoded(), "archivos/privateKey.key");

            System.out.println("Llaves generadas y guardadas en la carpeta 'archivos'.");

        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error al generar la pareja de llaves: " + e.getMessage());
        } catch (IOException e) {
            System.out.println("Error al guardar las llaves en archivos: " + e.getMessage());
        }
    }

    // Método auxiliar para guardar una llave en un archivo
    private void guardarLlaveEnArchivo(byte[] llave, String nombreArchivo) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(nombreArchivo)) {
            fos.write(llave);
        }
    }

    // Método para mostrar el menú
    public void mostrarMenu() {
        Scanner scanner = new Scanner(System.in);
        int opcion;

        do {
            System.out.println("\n--- Menú del Servidor ---");
            System.out.println("1. Generar pareja de llaves y guardarlas en archivos");
            System.out.println("2. Opción futura");
            System.out.println("0. Salir");
            System.out.print("Seleccione una opción: ");
            opcion = scanner.nextInt();

            switch (opcion) {
                case 1:
                    generarLlaves();
                    break;
                case 2:
                    System.out.println("Opción futura. No hay acción en esta opción.");
                    break;
                case 0:
                    System.out.println("Saliendo del servidor...");
                    break;
                default:
                    System.out.println("Opción inválida. Por favor, intente de nuevo.");
            }
        } while (opcion != 0);

        scanner.close();
    }

    public static void main(String[] args) {
        Servidor servidor = new Servidor();
        servidor.mostrarMenu(); // Muestra el menú
    }
}
