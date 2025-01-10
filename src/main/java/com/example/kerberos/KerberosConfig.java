package com.example.kerberos;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class KerberosConfig {
    private String principal;
    private String keytabPath;
    private String krb5ConfPath;
    
    public KerberosConfig() {
        loadProperties();
    }
    
    private void loadProperties() {
        Properties props = new Properties();
        try {
            props.load(new FileInputStream("src/main/resources/application.properties"));
            this.principal = props.getProperty("kerberos.principal");
            this.keytabPath = props.getProperty("kerberos.keytab.path");
            this.krb5ConfPath = props.getProperty("kerberos.krb5.conf.path");
        } catch (IOException e) {
            throw new RuntimeException("Failed to load properties", e);
        }
    }

    public String getPrincipal() {
        return principal;
    }

    public String getKeytabPath() {
        return keytabPath;
    }

    public String getKrb5ConfPath() {
        return krb5ConfPath;
    }
} 