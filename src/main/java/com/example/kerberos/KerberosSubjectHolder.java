package com.example.kerberos;

import javax.security.auth.Subject;
import java.security.PrivilegedAction;
import java.util.concurrent.ConcurrentHashMap;

public class KerberosSubjectHolder {
    private static final ConcurrentHashMap<String, Subject> subjects = new ConcurrentHashMap<>();

    public static void storeSubject(String key, Subject subject) {
        subjects.put(key, subject);
    }

    public static <T> T doAs(String key, PrivilegedAction<T> action) {
        Subject subject = subjects.get(key);
        if (subject == null) {
            throw new IllegalStateException("No subject found for key: " + key);
        }
        return Subject.doAs(subject, action);
    }

    public static void removeSubject(String key) {
        subjects.remove(key);
    }
} 