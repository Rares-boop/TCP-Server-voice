import chat.GroupChat;
import chat.GroupMember;
import chat.Message;
import chat.User;
import io.github.cdimascio.dotenv.Dotenv;

import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import chat.ChatDtos;

public class Database {
    public static Dotenv dotenv = Dotenv.load();
    public static String connString = "jdbc:postgresql://" + dotenv.get("DB_HOST")
            +":"+dotenv.get("DB_PORT")+"/"+dotenv.get("DB_DATABASE");
    public static String user = dotenv.get("DB_USER");
    public static String password = dotenv.get("DB_PASSWORD");
    private static final Logger logger = Logger.getLogger(Database.class.getName());
    public static void main(String[] args){
        System.out.println("DA");

        createTableUsers();
        createTableGroupChats();
        createTableGroupMembers();
        createTableUserLogs();
        createTableMessages();
        createTableOfflineQueue();
    }

    public static void createTableUsers(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                    CREATE TABLE IF NOT EXISTS USERS(
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(100) NOT NULL,
                        password_hash VARCHAR(255) NOT NULL,
                        salt VARCHAR(100) NOT NULL,
                        created_at BIGINT,
                        identity_key TEXT,
                        signed_pre_key TEXT,
                        signature TEXT
                    );
                    """;

            stmt.executeUpdate(query);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Failed to create USERS table", e);
        }
    }

    public static void insertUser(String username, String passwordHash,
                                  String salt, long createdAt){
        String query = """
            INSERT INTO users(username, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?)
            """;

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1,username);
            ps.setString(2,passwordHash);
            ps.setString(3,salt);
            ps.setLong(4, createdAt);

            ps.executeUpdate();
            logger.info("[DATABASE] User inserted successfully: " + username);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error inserting user: " + username, e);
        }
    }

    public static User selectUserByUsername(String usernameData){
        User userData = null;

        String query = """
                SELECT id, username, password_hash, salt, created_at, identity_key,
                signed_pre_key, signature
                FROM USERS WHERE username = ?;
               """;

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1,usernameData);
            ResultSet rs = ps.executeQuery();

            if (rs.next()){

                int id = rs.getInt("id");
                String username = rs.getString("username");
                String passwordHash = rs.getString("password_hash");
                String salt = rs.getString("salt");
                long createdAt = rs.getLong("created_at");

                String identityKey = rs.getString("identity_key");
                String signedPreKey = rs.getString("signed_pre_key");

                String signature = rs.getString("signature");

                userData = new User(id, username, passwordHash, salt, createdAt, identityKey,
                        signedPreKey, signature);
            }

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error selecting user by username: " + usernameData, e);
        }

        return userData;
    }

    public static List<String> selectUsersAddConversation(){
        List<String> users = new ArrayList<>();

        String query = "SELECT id, username FROM USERS";

        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            ResultSet rs = stmt.executeQuery(query);
            while (rs.next()){
                int id = rs.getInt("id");
                String username = rs.getString("username");
                users.add(id + "," + username);
            }

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error fetching users for conversation", e);
        }
        return users;
    }

    public static synchronized boolean updateUserKeys(int userId, String ik, String spk, String sig) {
        String query = "UPDATE users SET identity_key=?, signed_pre_key = ?, signature = ? WHERE id = ?";
        try (var connection = DriverManager.getConnection(connString, user, password);
        var ps = connection.prepareStatement(query)) {

            ps.setString(1,ik);
            ps.setString(2, spk);
            ps.setString(3, sig);
            ps.setInt(4, userId);

            int rows = ps.executeUpdate();

            return rows > 0;

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error updating keys for user " + userId, e);
            return false;
        }
    }

    public static synchronized ChatDtos.GetBundleResponseDto selectUserKeys(int targetUserId) {
        String query = "SELECT identity_key, signed_pre_key, signature FROM users WHERE id = ?";
        try (var conneciton = DriverManager.getConnection(connString, user, password);
        var ps = conneciton.prepareStatement(query)) {

            ps.setInt(1, targetUserId);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                String ik = rs.getString("identity_key");
                String spk = rs.getString("signed_pre_key");
                String sig = rs.getString("signature");

                if (ik == null || spk == null) return null;

                return new ChatDtos.GetBundleResponseDto(targetUserId, ik, spk, sig);
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error fetching keys for user " + targetUserId, e);
        }
        return null;
    }

    public static void createTableUserLogs(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt =connection.createStatement()){

                String query = """
                        CREATE TABLE IF NOT EXISTS USER_LOGS(
                            id SERIAL PRIMARY KEY,
                            id_user INTEGER,
                            action_type VARCHAR(100),
                            log_timestamp BIGINT,
                            ip_address VARCHAR(50),
                            FOREIGN KEY(id_user) REFERENCES USERS(id)
                        );
                        """;

                stmt.executeUpdate(query);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Failed to create USER_LOGS table", e);
        }
    }

    public static void insertUserLog(int userId, String actionType, long timestamp,
                                     String ipAddress){
        String query = """
                INSERT INTO USER_LOGS(id_user, action_type, log_timestamp, ip_address)
                VALUES(?, ?, ?, ?)
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1, userId);
            ps.setString(2, actionType);
            ps.setLong(3, timestamp);
            ps.setString(4, ipAddress);

            ps.executeUpdate();

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error inserting user log", e);
        }
    }

    public static void createTableGroupMembers(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                    CREATE TABLE IF NOT EXISTS GROUP_MEMBERS(
                        id_group INTEGER,
                        id_user INTEGER,
                        PRIMARY KEY(id_group, id_user),
                        FOREIGN KEY(id_group) REFERENCES GROUP_CHATS(id) ON DELETE CASCADE,
                        FOREIGN KEY(id_user) REFERENCES USERS(id) ON DELETE CASCADE
                    );
                    """;

                    stmt.executeUpdate(query);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Failed to create GROUP_MEMBERS table", e);
        }
    }

    public static void insertGroupMember(int groupId, int userId){
        String query = """
                INSERT INTO GROUP_MEMBERS(id_group, id_user) VALUES(?, ?)""";

        try(var connection=DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1,groupId);
            ps.setInt(2, userId);

            ps.executeUpdate();
            logger.info("[DATABASE] User " + userId + " added to Group " + groupId);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error inserting group member", e);
        }
    }

    public static List<GroupMember> selectGroupMembersByChatId(int groupId){
        List<GroupMember> currentChatGroupMembers = new ArrayList<>();
        String query = """
                SELECT id_group, id_user FROM GROUP_MEMBERS WHERE id_group = ?""";
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1, groupId);
            ResultSet rs = ps.executeQuery();

            while (rs.next()){
                int groupIdDatabase = rs.getInt(1);
                int userId = rs.getInt(2);

                currentChatGroupMembers.add(new GroupMember(groupIdDatabase, userId));
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error fetching group members for group " + groupId, e);
        }

        return  currentChatGroupMembers;
    }

    public static boolean deleteGroupChatTransactional(int chatId){
        String deleteMessages = "DELETE FROM MESSAGES WHERE id_group=?";
        String deleteGroupMembers = "DELETE FROM GROUP_MEMBERS WHERE id_group=?";

        String deleteGroupChat = "DELETE FROM GROUP_CHATS WHERE id=?";
        try(var connection = DriverManager.getConnection(connString, user, password)){
            connection.setAutoCommit(false);

            try(PreparedStatement psMessages = connection.prepareStatement(deleteMessages);
            PreparedStatement psGroupMembers = connection.prepareStatement(deleteGroupMembers);
            PreparedStatement psGroupChat = connection.prepareStatement(deleteGroupChat)){

                psMessages.setInt(1, chatId);
                psMessages.executeUpdate();

                psGroupMembers.setInt(1, chatId);
                psGroupMembers.executeUpdate();

                psGroupChat.setInt(1, chatId);
                int affectedRows = psGroupChat.executeUpdate();

                connection.commit();
                return affectedRows > 0;
            }
            catch (SQLException e){
                connection.rollback();
                logger.log(Level.SEVERE, "[DATABASE] Transaction failed. Rolled back chat deletion: " + chatId, e);

                return false;

            }finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error during transactional group delete", e);
            return false;
        }
    }

    public static void createTableGroupChats(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                    CREATE TABLE IF NOT EXISTS GROUP_CHATS(
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(200) NOT NULL
                    );
                    """;

                    stmt.executeUpdate(query);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Failed to create GROUP_CHATS table", e);
        }
    }

    public static List<GroupChat> selectGroupChatsByUserId(int userId){
        List<GroupChat> currentUserGroupChats = new ArrayList<>();
        String query = """
                SELECT GROUP_CHATS.id, GROUP_CHATS.name
                FROM GROUP_CHATS JOIN GROUP_MEMBERS ON
                GROUP_CHATS.id = GROUP_MEMBERS.id_group
                WHERE id_user=?""";

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1, userId);
            ResultSet rs = ps.executeQuery();

            while (rs.next()){
                int id = rs.getInt(1);
                String name = rs.getString(2);

                currentUserGroupChats.add(new GroupChat(id, name));
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error fetching group chats for user " + userId, e);
        }
        return currentUserGroupChats;
    }

    public static void insertGroupChat(String name){
        String query = """
                INSERT INTO GROUP_CHATS(name) VALUES(?)""";
        try(var connection =DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1, name);

            ps.executeUpdate();
            logger.info("[DATABASE] Group chat inserted: " + name);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error inserting group chat", e);
        }
    }

    public static GroupChat selectGroupChatByName(String groupChatName){
        GroupChat groupChat = null;
        String query = "SELECT * FROM GROUP_CHATS WHERE name=?";

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1, groupChatName);

            ResultSet rs = ps.executeQuery();

            if(rs.next()){
                int id = rs.getInt("id");
                String name = rs.getString("name");

                groupChat = new GroupChat(id, name);
            }

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error fetching group chat by name: " + groupChatName, e);
        }

        return groupChat;
    }

    public static boolean updateGroupChatName(int chatId, String newName){
        String query = "UPDATE GROUP_CHATS SET name=? WHERE id=?";
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setString(1, newName);
            ps.setInt(2, chatId);

            int rows = ps.executeUpdate();
            return rows > 0;

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error updating group chat name", e);
            return false;
        }
    }

    public static void createTableMessages(){
        try(var connection=DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                    CREATE TABLE IF NOT EXISTS MESSAGES(
                        id SERIAL PRIMARY KEY,
                        content BYTEA NOT NULL,
                        log_timestamp BIGINT NOT NULL,
                        id_sender INTEGER NOT NULL,
                        id_group INTEGER NOT NULL,
                        FOREIGN KEY(id_sender) REFERENCES USERS(id) ON DELETE CASCADE,
                        FOREIGN KEY(id_group) REFERENCES GROUP_CHATS(id) ON DELETE CASCADE
                    );
                    """;

            stmt.executeUpdate(query);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Failed to create MESSAGES table", e);
        }
    }

    public static int insertMessageReturningId(byte[] content, long timestamp, int senderId, int groupId){
        int id = -1;
        String query = """
                INSERT INTO MESSAGES(content, log_timestamp, id_sender, id_group)
                VALUES(?,?,?,?) RETURNING id;
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
            PreparedStatement ps = connection.prepareStatement(query)){

            ps.setBytes(1, content);
            ps.setLong(2, timestamp);
            ps.setInt(3, senderId);
            ps.setInt(4, groupId);

            ResultSet rs = ps.executeQuery();
            if(rs.next()){
                id = rs.getInt(1);
            }

            logger.info("[DATABASE] Message inserted successfully, ID: " + id);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error inserting message", e);
        }
        return id;
    }

    public static List<Message> selectMessagesByGroup(int groupId){
        List<Message> groupMessages = new ArrayList<>();
        String query = "SELECT * FROM MESSAGES WHERE id_group=?";

        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){
            ps.setInt(1,groupId);
            ResultSet rs = ps.executeQuery();

            while (rs.next()){
                int id = rs.getInt(1);
                byte[] content = rs.getBytes(2);
                long timestamp = rs.getLong(3);
                int senderId = rs.getInt(4);
                int groupIdDatabase = rs.getInt(5);

                groupMessages.add(new Message(id, content, timestamp, senderId, groupIdDatabase));
            }
        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error fetching messages for group " + groupId, e);
        }
        return groupMessages;
    }

    public static boolean updateMessageById(int id, byte[] newContent){
        String query = """
                UPDATE MESSAGES SET content=? WHERE id=?;
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setBytes(1,newContent);
            ps.setInt(2,id);

            int rows = ps.executeUpdate();

            return rows > 0;

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error updating message ID: " + id, e);
            return false;
        }
    }

    public static boolean deleteMessageById(int id){
        String query = """
                DELETE FROM MESSAGES WHERE id=?
                """;
        try(var connection = DriverManager.getConnection(connString, user, password);
        PreparedStatement ps = connection.prepareStatement(query)){

            ps.setInt(1, id);

            int rows = ps.executeUpdate();

            return rows > 0;

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error deleting message ID: " + id, e);
            return false;
        }
    }

    public static void createTableOfflineQueue(){
        try(var connection = DriverManager.getConnection(connString, user, password);
        var stmt = connection.createStatement()){

            String query = """
                CREATE TABLE IF NOT EXISTS OFFLINE_QUEUE(
                id SERIAL PRIMARY KEY,
                id_user INTEGER NOT NULL,
                packet_content TEXT NOT NULL,
                created_at BIGINT,
                FOREIGN KEY(id_user) REFERENCES USERS(id) ON DELETE CASCADE
                );
                """;

            stmt.executeUpdate(query);

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Failed to create OFFLINE_QUEUE table", e);
        }
    }

    public static void insertPendingPacket(int targetId, String jsonPacket) {
        String query = "INSERT INTO OFFLINE_QUEUE (id_user, packet_content, created_at) VALUES (?, ?, ?)";
        try (var connection = DriverManager.getConnection(connString, user, password);
        var  ps = connection.prepareStatement(query)) {

            ps.setInt(1, targetId);
            ps.setString(2, jsonPacket);

            ps.setLong(3, System.currentTimeMillis());
            ps.executeUpdate();

        } catch (SQLException e){
            logger.log(Level.SEVERE, "[DATABASE] Error inserting pending packet for user " + targetId, e);
        }
    }

    public static List<String> getAndClearPendingPackets(int userId) {
        List<String> queue = new ArrayList<>();

        String selectQuery = "SELECT packet_content FROM OFFLINE_QUEUE WHERE id_user = ? ORDER BY id ASC";
        String deleteQuery = "DELETE FROM OFFLINE_QUEUE WHERE id_user = ?";

        try (var connection = DriverManager.getConnection(connString, user, password)) {
            connection.setAutoCommit(false);

            try (var ps = connection.prepareStatement(selectQuery)) {
                ps.setInt(1, userId);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        queue.add(rs.getString("packet_content"));
                    }
                }
            }

            if (!queue.isEmpty()) {
                try (var delStmt = connection.prepareStatement(deleteQuery)) {
                    delStmt.setInt(1, userId);
                    delStmt.executeUpdate();
                }
                connection.commit();
                logger.info("[OFFLINE] Delivered " + queue.size() + " packets to User " + userId);
            } else {
                connection.rollback();
            }

        } catch (SQLException e) {
            logger.log(Level.SEVERE, "[DATABASE] Error clearing pending packets for user " + userId, e);
        }
        return queue;
    }
}


