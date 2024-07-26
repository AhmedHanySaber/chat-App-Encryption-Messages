package chat;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ChatServer {
    private static Set<ClientHandler> clientHandlers = new HashSet<>();

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("Server started...");

        while (true) {
            Socket socket = serverSocket.accept();
            ClientHandler clientHandler = new ClientHandler(socket);
            clientHandlers.add(clientHandler);
            new Thread(clientHandler).start();
        }
    }

    public static void broadcast(String message, ClientHandler excludeUser) {
        for (ClientHandler client : clientHandlers) {
            if (client != excludeUser) {
                client.sendMessage(message);
            }
        }
    }

    public static void sendToUser(String message, String username) {
        for (ClientHandler client : clientHandlers) {
            if (client.getUsername().equals(username)) {
                client.sendMessage(message);
                break;
            }
        }
    }

    public static void removeClient(ClientHandler clientHandler) {
        clientHandlers.remove(clientHandler);
    }
}

class ClientHandler implements Runnable {
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private String username;
    private SecretKey secretKey;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            // Read the username
            username = in.readLine();

            // Perform Diffie-Hellman key exchange
            KeyPair keyPair = generateKeyPair();
            byte[] publicKeyEncoded = keyPair.getPublic().getEncoded();
            out.println(Base64.getEncoder().encodeToString(publicKeyEncoded));

            String clientPublicKeyStr = in.readLine();
            byte[] clientPublicKeyEncoded = Base64.getDecoder().decode(clientPublicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPublicKeyEncoded);
            PublicKey clientPublicKey = keyFactory.generatePublic(x509KeySpec);

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(clientPublicKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();
            secretKey = new SecretKeySpec(sharedSecret, 0, 16, "AES");

            String clientMessage;
            while ((clientMessage = in.readLine()) != null) {
                // Assume the message format is "targetUsername:encryptedMessage"
                String[] parts = clientMessage.split(":", 2);
                String targetUsername = parts[0];
                String encryptedMessage = parts[1];

                if (targetUsername.equals("all")) {
                    ChatServer.broadcast(encryptedMessage, this);
                } else {
                    ChatServer.sendToUser(encryptedMessage, targetUsername);
                }
            }
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        } finally {
            try {
                socket.close();
                ChatServer.removeClient(this);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public void sendMessage(String message) {
        out.println(message);
    }
}
