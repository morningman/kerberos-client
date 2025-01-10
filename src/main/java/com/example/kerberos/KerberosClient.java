package com.example.kerberos;

import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class KerberosClient {
    private final String principal;
    private final String keytabPath;
    private final String krb5ConfPath;
    private final String loginContextName;
    private LoginContext loginContext;

    public KerberosClient(String principal, String keytabPath, String krb5ConfPath) {
        this.principal = principal;
        this.keytabPath = keytabPath;
        this.krb5ConfPath = krb5ConfPath;
        this.loginContextName = "KerberosLogin-" + UUID.randomUUID().toString();
    }

    public void login() throws LoginException {
        // 设置 krb5.conf 路径（如果需要）
        if (krb5ConfPath != null) {
            System.setProperty("java.security.krb5.conf", krb5ConfPath);
        }

        // 创建特定于此实例的 Configuration
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

                return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options
                    )
                };
            }
        };

        // 使用特定的 Configuration 创建 LoginContext
        loginContext = new LoginContext(loginContextName, null, null, config);
        loginContext.login();
    }

    public <T> T doAs(PrivilegedAction<T> action) {
        if (loginContext == null) {
            throw new IllegalStateException("Must call login() first");
        }
        return Subject.doAs(loginContext.getSubject(), action);
    }

    public void logout() throws LoginException {
        if (loginContext != null) {
            loginContext.logout();
        }
    }

    // 线程安全的使用示例
    public static void main(String[] args) {
        // 创建两个不同的客户端
        KerberosClient client1 = new KerberosClient(
            "user1@REALM.COM",
            "/path/to/user1.keytab",
            "/etc/krb5.conf"
        );

        KerberosClient client2 = new KerberosClient(
            "user2@REALM.COM",
            "/path/to/user2.keytab",
            "/etc/krb5.conf"
        );

        // 创建两个线程，分别使用不同的客户端
        Thread thread1 = new Thread(() -> {
            try {
                client1.login();
                for (int i = 0; i < 5; i++) {
                    client1.doAs((PrivilegedAction<Void>) () -> {
                        System.out.println("Thread 1: Executing as user1");
                        return null;
                    });
                    Thread.sleep(1000);
                }
                client1.logout();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        Thread thread2 = new Thread(() -> {
            try {
                client2.login();
                for (int i = 0; i < 5; i++) {
                    client2.doAs((PrivilegedAction<Void>) () -> {
                        System.out.println("Thread 2: Executing as user2");
                        return null;
                    });
                    Thread.sleep(1000);
                }
                client2.logout();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        thread1.start();
        thread2.start();
    }
} 