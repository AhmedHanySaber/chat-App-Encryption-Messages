package chat;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient {
    private static final String SERVER_ADDRESS = "localhost";
    private static final int SERVER_PORT = 12345;
    private static SecretKey secretKey;
    private static String username;

    public static void main(String[] args) throws Exception {
        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter your username: ");
        username = userInput.readLine();

        Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

        // Send username to the server
        writer.println(username);

        KeyPair keyPair = generateKeyPair();
        byte[] publicKeyEncoded = keyPair.getPublic().getEncoded();
        writer.println(Base64.getEncoder().encodeToString(publicKeyEncoded));

        String serverPublicKeyStr = reader.readLine();
        byte[] serverPublicKeyEncoded = Base64.getDecoder().decode(serverPublicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublicKeyEncoded);
        PublicKey serverPublicKey = keyFactory.generatePublic(x509KeySpec);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

        new Thread(new IncomingReader(reader)).start();

        String input;
        while ((input = userInput.readLine()) != null) {
            System.out.print("Enter target username (or 'all' for broadcast): ");
            String targetUsername = userInput.readLine();
            String encryptedMessage = encrypt(input);
            writer.println(targetUsername + ":" + encryptedMessage);
        }
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(message);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    private static class IncomingReader implements Runnable {
        private BufferedReader reader;

        public IncomingReader(BufferedReader reader) {
            this.reader = reader;
        }

        @Override
        public void run() {
            String message;
            try {
                while ((message = reader.readLine()) != null) {
                    String decryptedMessage = decrypt(message);
                    System.out.println("Received: " + decryptedMessage);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
