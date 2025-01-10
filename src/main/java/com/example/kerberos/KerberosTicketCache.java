package com.example.kerberos;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.*;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class KerberosTicketCache {
    // MIT Kerberos ticket cache format constants
    private static final byte[] MAGIC_HEADER = {0x05, 0x04, 0x00, 0x00};  // File format version 4
    private static final int TKT_FLG_INITIAL = 0x00400000;
    private static final int TKT_FLG_PRE_AUTH = 0x00200000;
    private static final int TKT_FLG_RENEWABLE = 0x00800000;
    private static final int TKT_FLG_FORWARDABLE = 0x40000000;
    private static final int TKT_FLG_FORWARDED = 0x20000000;
    private static final int TKT_FLG_PROXIABLE = 0x10000000;
    private static final int TKT_FLG_PROXY = 0x08000000;
    private static final int TKT_FLG_POSTDATED = 0x02000000;

    private final String principal;
    private final String keytabPath;
    private final String krb5ConfPath;
    private final String ticketCachePath;
    private LoginContext loginContext;

    public KerberosTicketCache(String principal, String keytabPath, String krb5ConfPath, String ticketCachePath) {
        this.principal = principal;
        this.keytabPath = keytabPath;
        this.krb5ConfPath = krb5ConfPath;
        this.ticketCachePath = ticketCachePath;
    }

    public void login() throws LoginException, IOException {
        // Set krb5.conf path if provided
        if (krb5ConfPath != null) {
            System.setProperty("java.security.krb5.conf", krb5ConfPath);
        }

        // Create parent directory for ticket cache if it doesn't exist
        File ticketFile = new File(ticketCachePath);
        File parentDir = ticketFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        // Configure JAAS login
        Configuration config = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("keyTab", keytabPath);
                options.put("principal", principal);
                options.put("storeKey", "true");
                options.put("doNotPrompt", "true");
                options.put("useKeyTab", "true");
                options.put("isInitiator", "true");
                options.put("refreshKrb5Config", "true");

                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options
                    )
                };
            }
        };

        // Login and get tickets
        loginContext = new LoginContext("KerberosLogin", null, null, config);
        loginContext.login();

        // Get tickets from subject
        Subject subject = loginContext.getSubject();
        Set<KerberosTicket> tickets = subject.getPrivateCredentials(KerberosTicket.class);
        Set<KerberosPrincipal> principals = subject.getPrincipals(KerberosPrincipal.class);

        if (!tickets.isEmpty() && !principals.isEmpty()) {
            writeTicketCache(tickets, principals.iterator().next());
        } else {
            throw new LoginException("No Kerberos tickets found after login");
        }
    }

    public void loginWithCache() throws LoginException {
        // Set krb5.conf path if provided
        if (krb5ConfPath != null) {
            System.setProperty("java.security.krb5.conf", krb5ConfPath);
        }

        // Verify ticket cache exists
        File ticketFile = new File(ticketCachePath);
        if (!ticketFile.exists()) {
            throw new LoginException("Ticket cache file not found: " + ticketCachePath);
        }

        // Configure JAAS login to use ticket cache
        Configuration config = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, String> options = new HashMap<>();
                options.put("principal", principal);
                options.put("useTicketCache", "true");
                options.put("ticketCache", ticketCachePath);
                options.put("renewTGT", "true");
                options.put("doNotPrompt", "true");
                options.put("useKeyTab", "false");
                options.put("isInitiator", "true");
                options.put("refreshKrb5Config", "true");

                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options
                    )
                };
            }
        };

        // Login using ticket cache
        loginContext = new LoginContext("KerberosLogin", null, null, config);
        loginContext.login();
    }

    private void writeTicketCache(Set<KerberosTicket> tickets, KerberosPrincipal defaultPrincipal) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(ticketCachePath))) {
            // Write file header (version 4)
            dos.write(MAGIC_HEADER);

            // Write default principal
            writePrincipal(dos, defaultPrincipal);

            // Write all credentials
            for (KerberosTicket ticket : tickets) {
                writeCredential(dos, ticket);
            }
        }

        // Set file permissions
        File ticketFile = new File(ticketCachePath);
        ticketFile.setReadable(true, true);
        ticketFile.setWritable(true, true);
    }

    private void writePrincipal(DataOutputStream dos, KerberosPrincipal principal) throws IOException {
        // Write principal type
        writeInt(dos, principal.getNameType());

        // Parse principal components
        String[] components = principal.getName().split("@");
        String[] nameComponents = components[0].split("/");
        String realm = components[1];

        // Write number of components
        writeInt(dos, nameComponents.length);

        // Write realm
        byte[] realmBytes = realm.getBytes("UTF-8");
        writeInt(dos, realmBytes.length);
        dos.write(realmBytes);

        // Write components
        for (String component : nameComponents) {
            byte[] componentBytes = component.getBytes("UTF-8");
            writeInt(dos, componentBytes.length);
            dos.write(componentBytes);
        }
    }

    private void writeCredential(DataOutputStream dos, KerberosTicket ticket) throws IOException {
        // Write client principal
        writePrincipal(dos, ticket.getClient());

        // Write server principal
        writePrincipal(dos, ticket.getServer());

        // Write key block
        int keyType = ticket.getSessionKeyType();
        if (keyType == 0) {
            keyType = 18; // Default to ENCTYPE_AES256_CTS_HMAC_SHA1_96
        }
        writeShort(dos, keyType);

        byte[] keyData = ticket.getSessionKey().getEncoded();
        writeInt(dos, keyData.length);
        dos.write(keyData);

        // Write times
        writeInt(dos, (int)(ticket.getAuthTime().getTime() / 1000));
        writeInt(dos, (int)(ticket.getStartTime().getTime() / 1000));
        writeInt(dos, (int)(ticket.getEndTime().getTime() / 1000));
        writeInt(dos, ticket.getRenewTill() != null ? (int)(ticket.getRenewTill().getTime() / 1000) : 0);

        // Write is_skey flag (usually 0)
        dos.write(0);

        // Write ticket flags
        int flags = TKT_FLG_INITIAL | TKT_FLG_PRE_AUTH;
        if (ticket.isForwardable()) flags |= TKT_FLG_FORWARDABLE;
        if (ticket.isForwarded()) flags |= TKT_FLG_FORWARDED;
        if (ticket.isProxiable()) flags |= TKT_FLG_PROXIABLE;
        if (ticket.isProxy()) flags |= TKT_FLG_PROXY;
        if (ticket.isPostdated()) flags |= TKT_FLG_POSTDATED;
        if (ticket.isRenewable()) flags |= TKT_FLG_RENEWABLE;
        writeInt(dos, flags);

        // Write empty address list
        writeInt(dos, 0);

        // Write empty authdata list
        writeInt(dos, 0);

        // Write ticket data
        byte[] encodedTicket = ticket.getEncoded();
        writeInt(dos, encodedTicket.length);
        dos.write(encodedTicket);

        // Write empty second ticket
        writeInt(dos, 0);
    }

    private void writeInt(DataOutputStream dos, int value) throws IOException {
        dos.writeInt(value);
    }

    private void writeShort(DataOutputStream dos, int value) throws IOException {
        dos.writeShort(value);
    }

    public void logout() throws LoginException {
        if (loginContext != null) {
            loginContext.logout();
        }
    }

    public <T> T doAs(PrivilegedAction<T> action) {
        if (loginContext == null) {
            throw new IllegalStateException("Must call login first");
        }
        return Subject.doAs(loginContext.getSubject(), action);
    }

    public static void main(String[] args) {
        try {
            // Set up test paths
            String baseDir = System.getProperty("user.dir") + "/kerberos/cache";
            String ticketCachePath = baseDir + "/krb5cc_test";

            // Clean up and create cache directory
            File cacheDir = new File(baseDir);
            if (cacheDir.exists()) {
                File[] files = cacheDir.listFiles();
                if (files != null) {
                    for (File file : files) {
                        file.delete();
                    }
                }
            }
            cacheDir.mkdirs();

            // Step 1: Create client and login with keytab
            System.out.println("\n=== Step 1: Login with Keytab ===");
            KerberosTicketCache client1 = new KerberosTicketCache(
                "hdfs/master-1-1.c-0596176698bd4d17.cn-beijing.emr.aliyuncs.com@EMR.C-0596176698BD4D17.COM",
                "/Users/morningman/workspace/git/kerberos-client/kerberos/hdfs.keytab",
                "/Users/morningman/workspace/git/kerberos-client/kerberos/krb5.conf",
                ticketCachePath
            );

            // Login with keytab and create ticket cache
            System.out.println("Logging in with keytab...");
            client1.login();
            System.out.println("Successfully created ticket cache at: " + ticketCachePath);

            // Test the credentials
            client1.doAs(() -> {
                System.out.println("Successfully executed privileged action with keytab credentials");
                return null;
            });

            client1.logout();

            // Step 2: Create new client and login with cached ticket
            System.out.println("\n=== Step 2: Login with Cached Ticket ===");
            KerberosTicketCache client2 = new KerberosTicketCache(
                "hdfs/master-1-1.c-0596176698bd4d17.cn-beijing.emr.aliyuncs.com@EMR.C-0596176698BD4D17.COM",
                null,  // No keytab needed
                "/Users/morningman/workspace/git/kerberos-client/kerberos/krb5.conf",
                ticketCachePath
            );

            // Login using cached ticket
            System.out.println("Logging in with ticket cache...");
            client2.loginWithCache();
            System.out.println("Successfully logged in using ticket cache");

            // Test the credentials
            client2.doAs(() -> {
                System.out.println("Successfully executed privileged action with cached credentials");
                return null;
            });

            client2.logout();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
} 