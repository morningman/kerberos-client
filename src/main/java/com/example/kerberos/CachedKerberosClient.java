package com.example.kerberos;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.File;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class CachedKerberosClient {
    private final String principal;
    private final String keytabPath;
    private final String krb5ConfPath;
    private final String ticketCachePath;
    private final String loginContextName;
    private LoginContext loginContext;
    private boolean useKeytab;

    /**
     * 从配置文件创建一个新的 CachedKerberosClient 实例
     */
    public CachedKerberosClient() {
        KerberosConfig config = new KerberosConfig();
        this.principal = config.getPrincipal();
        this.keytabPath = config.getKeytabPath();
        this.krb5ConfPath = config.getKrb5ConfPath();
        this.ticketCachePath = "/tmp/krb5cc_" + System.getProperty("user.name");
        this.loginContextName = "KerberosLogin-" + UUID.randomUUID().toString();
        this.useKeytab = true;
    }

    /**
     * 创建一个新的 CachedKerberosClient 实例
     * @param principal Kerberos principal
     * @param keytabPath keytab文件路径
     * @param krb5ConfPath krb5.conf文件路径
     * @param ticketCachePath ticket缓存文件路径
     */
    public CachedKerberosClient(String principal, String keytabPath, String krb5ConfPath, String ticketCachePath) {
        this.principal = principal;
        this.keytabPath = keytabPath;
        this.krb5ConfPath = krb5ConfPath;
        this.ticketCachePath = ticketCachePath;
        this.loginContextName = "KerberosLogin-" + UUID.randomUUID().toString();
        this.useKeytab = true;
    }

    /**
     * 使用keytab登录并将ticket缓存到指定位置
     */
    public void loginWithKeytabAndCache() throws LoginException {
        // 设置krb5.conf
        if (krb5ConfPath != null) {
            System.setProperty("java.security.krb5.conf", krb5ConfPath);
        }

        // 配置使用keytab登录并缓存ticket
        Configuration config = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                if (!loginContextName.equals(name)) {
                    return null;
                }

                Map<String, String> options = new HashMap<>();
                options.put("keyTab", keytabPath);
                options.put("principal", principal);
                options.put("storeKey", "true");
                options.put("doNotPrompt", "true");
                options.put("useKeyTab", "true");
                options.put("isInitiator", "true");
                options.put("ticketCache", ticketCachePath);
                options.put("useTicketCache", "true");
                options.put("renewTGT", "true");

                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options
                    )
                };
            }
        };

        loginContext = new LoginContext(loginContextName, null, null, config);
        loginContext.login();
    }

    /**
     * 使用缓存的ticket登录
     */
    public void loginWithCache() throws LoginException {
        useKeytab = false;
        
        if (krb5ConfPath != null) {
            System.setProperty("java.security.krb5.conf", krb5ConfPath);
        }

        // 验证ticket缓存文件是否存在
        File ticketFile = new File(ticketCachePath);
        if (!ticketFile.exists()) {
            throw new LoginException("Ticket cache file not found: " + ticketCachePath);
        }

        // 配置使用缓存的ticket登录
        Configuration config = new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                if (!loginContextName.equals(name)) {
                    return null;
                }

                Map<String, String> options = new HashMap<>();
                options.put("principal", principal);
                options.put("useTicketCache", "true");
                options.put("ticketCache", ticketCachePath);
                options.put("renewTGT", "true");
                options.put("doNotPrompt", "true");

                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options
                    )
                };
            }
        };

        loginContext = new LoginContext(loginContextName, null, null, config);
        loginContext.login();
    }

    public <T> T doAs(PrivilegedAction<T> action) {
        if (loginContext == null) {
            throw new IllegalStateException("Must call login first");
        }
        return Subject.doAs(loginContext.getSubject(), action);
    }

    public void logout() throws LoginException {
        if (loginContext != null) {
            loginContext.logout();
        }
    }

    // 使用示例
    public static void main(String[] args) {
        // 使用配置文件创建客户端实例
        CachedKerberosClient client = new CachedKerberosClient();

        try {
            // 首次使用keytab登录并缓存ticket
            System.out.println("First login with keytab...");
            client.loginWithKeytabAndCache();
            client.doAs((PrivilegedAction<Void>) () -> {
                System.out.println("Authenticated with keytab");
                return null;
            });
            client.logout();

            // 使用缓存的ticket重新登录
            System.out.println("\nSecond login using cached ticket...");
            client.loginWithCache();
            client.doAs((PrivilegedAction<Void>) () -> {
                System.out.println("Authenticated with cached ticket");
                return null;
            });
            client.logout();

        } catch (LoginException e) {
            e.printStackTrace();
        }
    }
} 