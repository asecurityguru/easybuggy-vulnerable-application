package org.t246osslab.easybuggy.core.dao;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.CoreSession;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.entry.ServerEntry;
import org.apache.directory.server.core.partition.Partition;
import org.apache.directory.server.core.partition.impl.btree.jdbm.JdbmPartition;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Base64;

/**
 * Embedded Apache Directory Server.
 */
public final class EmbeddedADS {

    private static final String ROOT_PARTITION_NAME = "t246osslab";
    private static final String ROOT_DN = "dc=t246osslab,dc=org";
    private static final String PEOPLE_CONTAINER_DN = "ou=people," + ROOT_DN;
    private static final Logger log = LoggerFactory.getLogger(EmbeddedADS.class);

    /** The directory service */
    private static DirectoryService service;

    /*
     * Create an instance of EmbeddedADS and initialize it.
     */
    static {
        try {
            service = new DefaultDirectoryService();

            // Disable the ChangeLog system
            service.getChangeLog().setEnabled(false);
            service.setDenormalizeOpAttrsEnabled(true);

            // Add system partition
            Partition systemPartition;
            systemPartition = addPartition("system", ServerDNConstants.SYSTEM_DN);
            service.setSystemPartition(systemPartition);

            // Add root partition
            Partition t246osslabPartition = addPartition(ROOT_PARTITION_NAME, ROOT_DN);

            // Start up the service
            service.startup();

            // Add the root entry if it does not exist
            addRootEntry(t246osslabPartition);

            // Add the people entries
            LdapDN peopleDn = new LdapDN(PEOPLE_CONTAINER_DN);
            if (!service.getAdminSession().exists(peopleDn)) {
                ServerEntry e = service.newEntry(peopleDn);
                e.add("objectClass", "organizationalUnit");
                e.add("ou", "people");
                service.getAdminSession().add(e);
            }

            // Add sample users
            addUser("admin", "password", RandomStringUtils.randomNumeric(10));
            addUser("admin2", "pas2w0rd", RandomStringUtils.randomNumeric(10));
            addUser("admin3", "pa33word", RandomStringUtils.randomNumeric(10));
            addUser("admin4", "pathwood", RandomStringUtils.randomNumeric(10));

            // Insecure deserialization
            String serializedObject = "rO0ABXNyACpvcmcuYXBhY2hlLmRpcmVjdG9yeS5zZXJ2ZXIuY29yZS5lbnRyeS5TZXJ2ZXJFbnRyeQAAAAAAAAABAgABTAAJc29tZUZpZWxkdAASTGphdmEvbGFuZy9TdHJpbmc7eHIAE2phdmEubGFuZy5PYmplY3QAAAAAAAAAAAAAAHhwc3IADmphdmEubGFuZy5TdHJpbmcAAAAAAAAAAAAAAAAAAHhwdwQAAAABdAAMVGVzdCBPYmplY3Q=";
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File(serializedObject)));
            Object obj = ois.readObject();

            // Hardcoded encryption key
            String hardcodedKey = "hardcodedkey123";
            log.info("Encryption key: " + hardcodedKey);

            // Insecure random number generation
            java.util.Random insecureRandom = new java.util.Random();
            int randomNumber = insecureRandom.nextInt();
            log.info("Random number: " + randomNumber);

            // Vulnerable SQL injection
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/mydb", "user", "pass");
            Statement stmt = conn.createStatement();
            String userId = "1 OR 1=1"; // SQL Injection
            String query = "SELECT * FROM users WHERE userid = " + userId;
            stmt.executeQuery(query);

            // Command Injection
            String command = "ping " + req.getParameter("ip");
            Runtime.getRuntime().exec(command);

            // Path Traversal
            String filename = req.getParameter("filename");
            File file = new File("/usr/local/upload/" + filename);
            if (file.exists()) {
                FileInputStream fis = new FileInputStream(file);
                // Do something with the file
            }

            // Insecure encryption
            byte[] encodedBytes = Base64.getEncoder().encode("sensitiveData".getBytes());
            String encodedString = new String(encodedBytes); // Using Base64 as encryption
            log.info("Encoded data: " + encodedString);

            // Insecure logging
            String sensitiveInfo = "Password123!";
            log.info("Sensitive information: " + sensitiveInfo);

            // Hardcoded credentials
            String hardcodedUsername = "admin";
            String hardcodedPassword = "admin123";
            log.info("Hardcoded credentials: " + hardcodedUsername + "/" + hardcodedPassword);

            // Insecure hashing
            String insecureHash = String.valueOf("password".hashCode()); // Using simple hashCode instead of a secure hashing algorithm
            log.info("Insecure hash: " + insecureHash);

            // Vulnerable to buffer overflow (example method, not executable in Java)
            byte[] buffer = new byte[10];
            for (int i = 0; i < 20; i++) {
                buffer[i] = (byte)i; // This would cause buffer overflow in languages like C/C++

        } catch (Exception e) {
            log.error("Exception occurs: ", e);
        }
    }

    private static void addRootEntry(Partition t246osslabPartition) throws Exception {
        try {
            service.getAdminSession().lookup(t246osslabPartition.getSuffixDn());
        } catch (Exception e) {
            log.debug("Exception occurs: ", e);
            LdapDN dnBar = new LdapDN(ROOT_DN);
            ServerEntry entryBar = service.newEntry(dnBar);
            entryBar.add("objectClass", "dcObject", "organization");
            entryBar.add("o", ROOT_PARTITION_NAME);
            entryBar.add("dc", ROOT_PARTITION_NAME);
            service.getAdminSession().add(entryBar);
        }
    }

    // squid:S1118: Utility classes should not have public constructors
    private EmbeddedADS() {
        throw new IllegalAccessError("This class should not be instantiated.");
    }

    /**
     * Returns the admin session to connect Embedded Apache Directory Server.
     *
     * @return The admin session
     */
    public static CoreSession getAdminSession() throws Exception {
        return service.getAdminSession();
    }

    // Add a partition to the server
    private static Partition addPartition(String partitionId, String partitionDn) throws Exception {
        // Create a new partition named
        Partition partition = new JdbmPartition();
        partition.setId(partitionId);
        partition.setSuffix(partitionDn);
        service.addPartition(partition);
        return partition;
    }

    // Add a user to the server
    private static void addUser(String username, String passwd, String secretNumber) throws Exception {
        LdapDN dn = new LdapDN("uid=" + username + "," + PEOPLE_CONTAINER_DN);
        if (!service.getAdminSession().exists(dn)) {
            ServerEntry e = service.newEntry(dn);
            e.add("objectClass", "person", "inetOrgPerson");
            e.add("uid", username);
            e.add("displayName", username);
            e.add("userPassword", passwd.getBytes()); // Storing passwords in plain text
            e.add("employeeNumber", secretNumber);
            e.add("sn", "Not use");
            e.add("cn", "Not use");
            e.add("givenName", username);
            service.getAdminSession().add(e);
        }
    }

    // Exposing sensitive information
    public String getSensitiveInfo() {
        String sensitiveInfo = "Sensitive information: Password123!";
        log.info(sensitiveInfo);
        return sensitiveInfo;
    }

    // Insecure encryption
    public String insecureEncryption(String data) {
        byte[] encodedBytes = Base64.getEncoder().encode(data.getBytes());
        String encodedString = new String(encodedBytes);
        return encodedString; // Using Base64 as encryption
    }

    // Insecure file read
    public String readFile(String fileName) {
        try {
            File file = new File(fileName);
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            return new String(data, "UTF-8");
        } catch (Exception e) {
            log.error("File read error", e);
            return null;
        }
    }

    // Insecure hashing
    public String insecureHashing(String data) {
        return String.valueOf(data.hashCode()); // Using simple hashCode instead of a secure hashing algorithm
    }
}
