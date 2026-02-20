import chat.*;
import com.google.gson.Gson;

import java.io.*;
import java.net.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;

public class TcpServer {
    private static final List<ClientHandler> clients = new ArrayList<>();
    public static final Map<Integer, InetSocketAddress> activeCallers = new ConcurrentHashMap<>();

    public static final Gson gson = new Gson();
    public static volatile KeyPair globalServerKyberKeys;

    public static volatile boolean isUdpServerRunning = true;
    private static final Logger logger = java.util.logging.Logger.getLogger(TcpServer.class.getName());

    public static void main(String[] args){
        try {
            globalServerKyberKeys = CryptoHelper.generateKyberKeys();
            System.out.println("SERVER PORNIT ");

            startKeyRotation();
            new Thread(TcpServer::tcpServer).start();

            new Thread(TcpServer::udpServer).start();

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Something went wrong", e);
        }
    }

    public static void startKeyRotation() {
        new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(30 * 60 * 1000);
                    System.out.println("[ROTATION] Generare chei Kyber noi...");

                    long start = System.currentTimeMillis();
                    globalServerKyberKeys = CryptoHelper.generateKyberKeys();

                    System.out.println("[ROTATION] Chei schimbate in " + (System.currentTimeMillis() - start) + "ms. Urmatoarea rotire in 30 min.");

                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error during Kyber key rotation", e);
                }
            }
        }).start();
    }

    public static void tcpServer(){
        try(ServerSocket serverSocket = new ServerSocket(15555)){
            while (true){

                Socket clientSocket = serverSocket.accept();
                logger.info("Client conectat: " + clientSocket.getInetAddress());

                ClientHandler handler = new ClientHandler(clientSocket);
                new Thread(handler).start();
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "PORT IN USE", e);
        }
    }

    public static void udpServer(){
        try(DatagramSocket udpSocket = new DatagramSocket(15556)){
            byte[] buffer = new byte[4096];

            System.out.println("[UDP] Server Voce pornit pe portul 15556");

            while (isUdpServerRunning){
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                udpSocket.receive(packet);

                //[ SENDER_ID (4 bytes) ] [ TARGET_ID (4 bytes) ] [ ENCRYPTED_AUDIO_BYTES ... ]
                DataInputStream dis = new DataInputStream(new ByteArrayInputStream(packet.getData()));

                int senderId = dis.readInt();
                int targetId = dis.readInt();

                InetSocketAddress senderAddr = new InetSocketAddress(packet.getAddress(), packet.getPort());
                activeCallers.put(senderId, senderAddr);

                if (activeCallers.containsKey(targetId)) {
                    InetSocketAddress targetAddr = activeCallers.get(targetId);

                    packet.setSocketAddress(targetAddr);
                    udpSocket.send(packet);

//                     System.out.println("Relay: " + senderId + " -> " + targetId + " (" + packet.getLength() + " bytes)");
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Critical error in UDP server", e);
        }
    }

    static class ClientHandler implements Runnable{
        private final Socket socket;
        private PrintWriter out;
        private BufferedReader in;

        private User currentUser = null;
        private int currentChatId = -1;
        private boolean isRunning = true;

        private SecretKey sessionKey = null;
        private PrivateKey tempKyberPrivate = null;

        public ClientHandler(Socket socket) {
            this.socket = socket;
            try{
                socket.setTcpNoDelay(true);

                this.out = new PrintWriter(socket.getOutputStream(), true);
                this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            } catch (IOException e) {
                logger.log(Level.SEVERE, "Error initializing I/O streams for client", e);
            }
        }

        @Override
        public void run() {
            try {
                if (!performHandshake()) {
                    System.out.println("Handshake Esuat.");
                    disconnect();
                    return;
                }

                while (isRunning) {
                    String jsonRequest = in.readLine();
                    if(jsonRequest==null){
                        break;
                    }

                    NetworkPacket packet = NetworkPacket.fromJson(jsonRequest);

                    if (packet.getType() == PacketType.SECURE_ENVELOPE) {
                        try {
                            String encryptedPayload = packet.getPayload().getAsString();
                            byte[] packedBytes = Base64.getDecoder().decode(encryptedPayload);

                            System.out.println("ENCRYPTED DATA: " + encryptedPayload);

                            String originalJson = CryptoHelper.unpackAndDecrypt(sessionKey, packedBytes);
                            packet = NetworkPacket.fromJson(originalJson);

                            System.out.println("Pachet Real: " + originalJson);

                        } catch (Exception e) {
                            System.out.println("Eroare decriptare Tunel!");
                            continue;
                        }
                    }
                    else {
                        System.out.println("Pachet necriptat refuzat: " + packet.getType());
                        continue;
                    }

                    switch (packet.getType()) {
                        case LOGIN_REQUEST: handleLogin(packet); break;
                        case REGISTER_REQUEST: handleRegister(packet); break;

                        case SEND_MESSAGE: handleSendMessage(packet); break;

                        case GET_CHATS_REQUEST: handleGetChats(); break;
                        case GET_USERS_REQUEST: handleGetUsersForAdd(); break;
                        case CREATE_CHAT_REQUEST: handleCreateChat(packet); break;
                        case DELETE_CHAT_REQUEST: handleDeleteChat(packet); break;
                        case RENAME_CHAT_REQUEST: handleRenameChat(packet); break;
                        case ENTER_CHAT_REQUEST: handleEnterChat(packet); break;
                        case EXIT_CHAT_REQUEST:
                            this.currentChatId = -1;
                            sendPacket(PacketType.EXIT_CHAT_RESPONSE, "BYE");
                            break;

                        case EDIT_MESSAGE_REQUEST: handleEditMessage(packet); break;
                        case DELETE_MESSAGE_REQUEST: handleDeleteMessage(packet); break;
                        case PUBLISH_KEYS:       handlePublishKeys(packet); break;
                        case GET_BUNDLE_REQUEST: handleGetBundle(packet); break;
                        case CALL_REQUEST: handleCallRequest(packet); break;
                        case CALL_ACCEPT:  handleCallAccept(packet); break;
                        case CALL_DENY:    handleCallDeny(packet); break;
                        case CALL_END:     handleCallEnd(packet); break;
                        case GET_CHAT_MEMBERS_REQUEST: handleGetChatMembers(packet); break;
                        case LOGOUT: disconnect(); break;

                        default: System.out.println("Unknown packet: " + packet.getType());
                    }
                }
            } catch (Exception e) {
                disconnect();
            }
        }

        private void handleLogin(NetworkPacket packet) throws IOException {
            ChatDtos.AuthDto dto = gson.fromJson(packet.getPayload(), ChatDtos.AuthDto.class);
            User user = Database.selectUserByUsername(dto.username);

            if (user != null && PasswordUtils.verifyPassword(dto.password, user.getSalt(), user.getPasswordHash())) {
                synchronized (clients) {
                    for (ClientHandler c : clients) {
                        if (c.currentUser != null && c.currentUser.getId() == user.getId()) {
                            sendPacket(PacketType.LOGIN_RESPONSE, "ALREADY"); return;
                        }
                    }
                    clients.add(this);
                }
                this.currentUser = user;
                Database.insertUserLog(user.getId(), "LOGIN", System.currentTimeMillis(), socket.getInetAddress().getHostAddress());
                sendPacket(PacketType.LOGIN_RESPONSE, user);

                System.out.println("[LOGIN] User " + user.getId() + " conectat.");

                new Thread(() -> {
                    try {
                        Thread.sleep(200);
                        List<String> missedPackets = Database.getAndClearPendingPackets(user.getId());

                        if (!missedPackets.isEmpty()) {
                            System.out.println("Livrez " + missedPackets.size() + " pachete offline catre User " + user.getId());

                            for (String json : missedPackets) {
                                NetworkPacket p = NetworkPacket.fromJson(json);
                                sendDirectPacket(p);

                                Thread.sleep(20);
                            }
                        }
                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "Error delivering offline packets", e);
                    }
                }).start();

            } else {
                sendPacket(PacketType.LOGIN_RESPONSE, "FAIL");
            }
        }

        private void handleSendMessage(NetworkPacket packet) throws IOException {
            Message receivedMsg = gson.fromJson(packet.getPayload(), Message.class);
            if (currentChatId == -1) return;

            long timestamp = System.currentTimeMillis();
            System.out.println("[MESSAGE ROUTING] Am primit un mesaj de la User " + currentUser.getId());

            int msgId = Database.insertMessageReturningId(
                    receivedMsg.getContent(),
                    timestamp,
                    currentUser.getId(),
                    currentChatId
            );

            Message fullMsg = new Message(msgId, receivedMsg.getContent(), timestamp, currentUser.getId(), currentChatId);

            String clearTextPreview = new String(receivedMsg.getContent());
            System.out.println("CONTINUT DECRIPTAT (Ce vede serverul): " + clearTextPreview);

            String encryptedPreview = Base64.getEncoder().encodeToString(fullMsg.getContent());
            System.out.println("CONTINUT (ENCTYPTED SERVER SIDE): " + encryptedPreview);

            broadcastToPartner(currentChatId, PacketType.RECEIVE_MESSAGE, fullMsg);

            sendPacket(PacketType.RECEIVE_MESSAGE, fullMsg);
        }

        private void broadcastToPartner(int chatId, PacketType type, Object payload) {
            List<GroupMember> members = Database.selectGroupMembersByChatId(chatId);

            for (GroupMember m : members) {
                int targetId = m.getUserId();
                if (targetId == currentUser.getId()) continue;

                NetworkPacket p = new NetworkPacket(type, currentUser.getId(), payload);

                synchronized (clients) {
                    for (ClientHandler client : clients) {
                        if (client.currentUser != null && client.currentUser.getId() == targetId) {
                            try {
                                client.sendDirectPacket(p);
                            } catch (IOException e) {}
                            break;
                        }
                    }
                }
            }
        }

        private boolean performHandshake() {
            try {
                System.out.println("Handshake...");

                KeyPair kyberPair = TcpServer.globalServerKyberKeys;
                KeyPair ecPair = CryptoHelper.generateECKeys();

                this.tempKyberPrivate = kyberPair.getPrivate();
                byte[] pubBytes = kyberPair.getPublic().getEncoded();

                String pubBase64 = Base64.getEncoder().encodeToString(pubBytes);
                String ecPubBase64 = Base64.getEncoder().encodeToString(ecPair.getPublic().getEncoded());

                String combinedPayload = pubBase64 + ":" + ecPubBase64;

                NetworkPacket hello = new NetworkPacket(PacketType.KYBER_SERVER_HELLO, 0, combinedPayload);
                synchronized (out){
                    out.println(hello.toJson());
                    out.flush();
                }

                String responseJson = in.readLine();
                NetworkPacket response = NetworkPacket.fromJson(responseJson);

                if (response.getType() == PacketType.KYBER_CLIENT_FINISH) {
                    String payload = response.getPayload().getAsString();
                    String[] parts = payload.split(":");

                    byte[] kyberCipherBytes = Base64.getDecoder().decode(parts[0]);
                    byte[] clientECPubBytes = Base64.getDecoder().decode(parts[1]);

                    SecretKey kyberSecret = CryptoHelper.decapsulate(this.tempKyberPrivate, kyberCipherBytes);

                    PublicKey clientECPub = CryptoHelper.decodeECPublicKey(clientECPubBytes);
                    byte[] ecSecret = CryptoHelper.doECDH(ecPair.getPrivate(), clientECPub);

                    this.sessionKey = CryptoHelper.combineSecrets(ecSecret, kyberSecret.getEncoded());
                    this.tempKyberPrivate = null;
                    System.out.println("Tunel OK!");
                    return true;
                }
                return false;
            } catch (Exception e) { return false; }
        }

        private void sendPacket(PacketType type, Object payload) throws IOException {
            int myId = (currentUser != null) ? currentUser.getId() : 0;
            NetworkPacket p = new NetworkPacket(type, myId, payload);
            sendDirectPacket(p);
        }

        private void sendDirectPacket(NetworkPacket p) throws IOException {
            if (sessionKey != null) {
                try {
                    String clearJson = p.toJson();
                    byte[] encryptedBytes = CryptoHelper.encryptAndPack(sessionKey, clearJson);
                    String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);
                    NetworkPacket envelope = new NetworkPacket(PacketType.SECURE_ENVELOPE, p.getSenderId(), encryptedBase64);
                    synchronized (out) { out.println(envelope.toJson()); out.flush(); }
                } catch (Exception e) { logger.log(Level.SEVERE, "Error encrypting/sending secure envelope", e); }
            } else {
                synchronized (out) { out.println(p.toJson()); out.flush(); }
            }
        }
        
        private void handleRegister(NetworkPacket packet) throws IOException {
            ChatDtos.AuthDto dto = gson.fromJson(packet.getPayload(), ChatDtos.AuthDto.class);
            if (Database.selectUserByUsername(dto.username) != null) { sendPacket(PacketType.REGISTER_RESPONSE, "EXISTS"); return; }
            String salt = PasswordUtils.generateSalt(50);
            String hash = PasswordUtils.hashPassword(dto.password, salt);
            Database.insertUser(dto.username, hash, salt, System.currentTimeMillis());
            User newUser = Database.selectUserByUsername(dto.username);
            this.currentUser = newUser;
            synchronized (clients) { clients.add(this); }
            sendPacket(PacketType.REGISTER_RESPONSE, newUser);
        }
        private void handleGetChats() throws IOException { if (currentUser != null) sendPacket(PacketType.GET_CHATS_RESPONSE, Database.selectGroupChatsByUserId(currentUser.getId())); }
        private void handleGetUsersForAdd() throws IOException {
            List<String> rawUsers = Database.selectUsersAddConversation();
            List<String> filtered = new ArrayList<>();
            for (String u : rawUsers) { int uid = Integer.parseInt(u.split(",")[0]); if (uid != currentUser.getId() && uid != -1) filtered.add(u); }
            sendPacket(PacketType.GET_USERS_RESPONSE, filtered);
        }

        private void handleEnterChat(NetworkPacket packet) throws IOException {
            int chatId = gson.fromJson(packet.getPayload(), Integer.class);
            this.currentChatId = chatId;
            sendPacket(PacketType.ENTER_CHAT_RESPONSE, "OK");
            List<Message> history = Database.selectMessagesByGroup(chatId);
            sendPacket(PacketType.GET_MESSAGES_RESPONSE, history);
        }

        private void handleCreateChat(NetworkPacket packet) throws IOException {
            ChatDtos.CreateGroupDto dto = gson.fromJson(packet.getPayload(), ChatDtos.CreateGroupDto.class);
            Database.insertGroupChat(dto.groupName);
            GroupChat newChat = Database.selectGroupChatByName(dto.groupName);

            if (newChat != null) {
                Database.insertGroupMember(newChat.getId(), currentUser.getId());
                Database.insertGroupMember(newChat.getId(), dto.targetUserId);

                ChatDtos.NewChatBroadcastDto packetForAlice = new ChatDtos.NewChatBroadcastDto(newChat, null);
                NetworkPacket pAlice = new NetworkPacket(PacketType.CREATE_CHAT_BROADCAST, currentUser.getId(), packetForAlice);
                sendDirectPacket(pAlice);

                ChatDtos.NewChatBroadcastDto packetForBob = new ChatDtos.NewChatBroadcastDto(newChat, dto.initialKeyCiphertext);
                NetworkPacket pBob = new NetworkPacket(PacketType.CREATE_CHAT_BROADCAST, currentUser.getId(), packetForBob);

                sendToSpecificUser(dto.targetUserId, pBob);

                System.out.println("[SERVER] Chat " + newChat.getId() + " creat. Ciphertext rutat catre User " + dto.targetUserId);
            }
        }

        private void handleRenameChat(NetworkPacket packet) throws IOException {
            ChatDtos.RenameGroupDto dto = gson.fromJson(packet.getPayload(), ChatDtos.RenameGroupDto.class);

            Database.updateGroupChatName(dto.chatId, dto.newName);
            NetworkPacket broadcastPacket = new NetworkPacket(PacketType.RENAME_CHAT_BROADCAST, currentUser.getId(), dto);

            sendDirectPacket(broadcastPacket);
            broadcastToChatMembers(dto.chatId, PacketType.RENAME_CHAT_BROADCAST, dto);
        }

        private void handleDeleteChat(NetworkPacket packet) throws IOException {
            int chatId = gson.fromJson(packet.getPayload(), Integer.class);

            List<GroupMember> members = Database.selectGroupMembersByChatId(chatId);
            Database.deleteGroupChatTransactional(chatId);

            NetworkPacket broadcastPacket = new NetworkPacket(PacketType.DELETE_CHAT_BROADCAST, currentUser.getId(), chatId);
            sendDirectPacket(broadcastPacket);

            for (GroupMember m : members) {
                if (m.getUserId() != currentUser.getId()) {
                    sendToSpecificUser(m.getUserId(), broadcastPacket);
                }
            }
        }

        private void sendToSpecificUser(int targetUserId, NetworkPacket p) {
            boolean isOnline = false;

            synchronized (clients) {
                for (ClientHandler client : clients) {
                    if (client.currentUser != null && client.currentUser.getId() == targetUserId) {
                        try {
                            client.sendDirectPacket(p);
                            isOnline = true;
                        } catch (IOException e) {
                            logger.log(Level.WARNING, "Eroare la trimitere catre client online: {0}", targetUserId);
                        }
                        break;
                    }
                }
            }

            if (!isOnline) {
                System.out.println("User " + targetUserId + " offline/inaccesibil. Salvez pachetul in coada...");
                String packetJson = p.toJson();

                Database.insertPendingPacket(targetUserId, packetJson);
            }
        }

        private void broadcastToChatMembers(int chatId, PacketType type, Object payload) {
            List<GroupMember> members = Database.selectGroupMembersByChatId(chatId);
            NetworkPacket p = new NetworkPacket(type, currentUser.getId(), payload);
            for (GroupMember m : members) {
                if (m.getUserId() != currentUser.getId()) {
                    sendToSpecificUser(m.getUserId(), p);
                }
            }
        }

        private void handleEditMessage(NetworkPacket packet) throws IOException {
            ChatDtos.EditMessageDto dto = gson.fromJson(packet.getPayload(), ChatDtos.EditMessageDto.class);
            if (Database.updateMessageById(dto.messageId, dto.newContent)) {
                if (currentChatId != -1) {
                    broadcastToPartner(currentChatId, PacketType.EDIT_MESSAGE_BROADCAST, dto);
                    sendPacket(PacketType.EDIT_MESSAGE_BROADCAST, dto);
                }
            }
        }
        private void handleDeleteMessage(NetworkPacket packet) throws IOException {
            int msgId = gson.fromJson(packet.getPayload(), Integer.class);
            if (Database.deleteMessageById(msgId)) {
                if (currentChatId != -1) {
                    broadcastToPartner(currentChatId, PacketType.DELETE_MESSAGE_BROADCAST, msgId);
                    sendPacket(PacketType.DELETE_MESSAGE_BROADCAST, msgId);
                }
            }
        }

        private void handlePublishKeys(NetworkPacket packet) {
            try {
                ChatDtos.PublishKeysDto dto = gson.fromJson(packet.getPayload(), ChatDtos.PublishKeysDto.class);

                System.out.println("[PGP] User " + currentUser.getId() + " publica chei noi...");

                boolean success = Database.updateUserKeys(
                        currentUser.getId(),
                        dto.identityKeyPublic,
                        dto.signedPreKeyPublic,
                        dto.signature
                );

                if (success) {
                    System.out.println("Chei salvate in DB pentru User " + currentUser.getId());
                } else {
                    System.out.println("Eroare la salvarea cheilor in DB!");
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error publishing keys to database", e);
            }
        }

        private void handleGetBundle(NetworkPacket packet){
            try {
                ChatDtos.GetBundleRequestDto req = gson.fromJson(packet.getPayload(), ChatDtos.GetBundleRequestDto.class);

                System.out.println("User " + currentUser.getId() + " cere cheile Userului " + req.targetUserId);

                ChatDtos.GetBundleResponseDto bundle = Database.selectUserKeys(req.targetUserId);

                if (bundle != null) {
                    sendPacket(PacketType.GET_BUNDLE_RESPONSE, bundle);
                    System.out.println("Bundle trimis catre " + currentUser.getId());
                } else {
                    System.out.println("Nu am gasit chei pentru User " + req.targetUserId + " (Poate nu are PGP activat)");
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error retrieving key bundle", e);
            }
        }

        private void handleCallRequest(NetworkPacket packet){
            int targetUserId = gson.fromJson(packet.getPayload(), Integer.class);
            System.out.println("[CALL] User " + currentUser.getId() + " suna pe " + targetUserId);

            NetworkPacket requestPacket = new NetworkPacket(PacketType.CALL_REQUEST, currentUser.getId(), currentUser.getId());
            sendToSpecificUser(targetUserId, requestPacket);
        }

        private void handleCallAccept(NetworkPacket packet){
            int callerId = gson.fromJson(packet.getPayload(), Integer.class);
            System.out.println("[CALL] User " + currentUser.getId() + " a raspuns lui " + callerId);

            NetworkPacket acceptPacket = new NetworkPacket(PacketType.CALL_ACCEPT, currentUser.getId(), currentUser.getId());
            sendToSpecificUser(callerId, acceptPacket);
        }

        private void handleCallDeny(NetworkPacket packet){
            int callerId = gson.fromJson(packet.getPayload(), Integer.class);
            System.out.println("[CALL] User " + currentUser.getId() + " a respins apelul lui " + callerId);

            NetworkPacket denyPacket = new NetworkPacket(PacketType.CALL_DENY, currentUser.getId(), "BUSY");
            sendToSpecificUser(callerId, denyPacket);
        }

        private void handleCallEnd(NetworkPacket packet){
            int partnerId = gson.fromJson(packet.getPayload(), Integer.class);
            System.out.println("[CALL] Apel terminat intre " + currentUser.getId() + " si " + partnerId);

            NetworkPacket endPacket = new NetworkPacket(PacketType.CALL_END, currentUser.getId(), "END");
            sendToSpecificUser(partnerId, endPacket);

            TcpServer.activeCallers.remove(currentUser.getId());
            TcpServer.activeCallers.remove(partnerId);
        }

        private void handleGetChatMembers(NetworkPacket packet) throws IOException {
            int requestedChatId = gson.fromJson(packet.getPayload(), Integer.class);
            List<GroupMember> members = Database.selectGroupMembersByChatId(requestedChatId);

            List<Integer> memberIds = new ArrayList<>();
            for (GroupMember m : members) {
                memberIds.add(m.getUserId());
            }

            sendPacket(PacketType.GET_CHAT_MEMBERS_RESPONSE, memberIds);
        }

        private void disconnect() {
            isRunning = false;
            synchronized (clients) { clients.remove(this); }
            try { socket.close(); } catch (IOException e) {}
            System.out.println("Client deconectat.");
        }
    }
}

