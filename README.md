# Kerberos 客户端

这是一个基于Java实现的Kerberos客户端库，提供了简单易用的Kerberos认证接口，支持keytab认证和ticket缓存机制。

## 功能特性

- 支持使用keytab文件进行Kerberos认证
- 支持ticket缓存机制，减少keytab文件访问
- 线程安全的实现，支持多个认证主体并发使用
- 提供简单的权限执行接口（doAs方法）
- 支持配置文件加载

## 主要组件

### KerberosConfig

配置加载类，负责从properties文件中加载Kerberos相关配置：
- principal名称
- keytab文件路径
- krb5.conf配置文件路径

### KerberosClient

基础的Kerberos客户端实现，提供以下功能：
- 使用keytab进行登录认证
- 执行权限操作
- 注销登录

### CachedKerberosClient

增强版的Kerberos客户端，在基础功能之上增加了ticket缓存支持：
- 支持使用keytab登录并缓存ticket
- 支持使用已缓存的ticket进行登录
- 减少对keytab文件的访问次数
- 支持从配置文件自动加载配置

### KerberosSubjectHolder

线程安全的Subject管理器：
- 支持存储多个认证主体
- 提供线程安全的访问方式
- 支持动态添加和移除认证主体

## 使用方法

### 1. 配置文件

在 `src/main/resources/application.properties` 中配置以下参数：

```properties
kerberos.principal=your_principal@YOUR.REALM
kerberos.keytab.path=/path/to/your.keytab
kerberos.krb5.conf.path=/etc/krb5.conf
```

### 2. 基础使用示例

```java
// 创建客户端实例
KerberosClient client = new KerberosClient(
    "user@REALM.COM",
    "/path/to/user.keytab",
    "/etc/krb5.conf"
);

try {
    // 登录
    client.login();
    
    // 执行需要认证的操作
    client.doAs(() -> {
        // 在这里执行需要Kerberos认证的操作
        return null;
    });
    
    // 注销
    client.logout();
} catch (LoginException e) {
    e.printStackTrace();
}
```

### 3. 使用缓存的示例

#### 3.1 使用配置文件（推荐）

```java
// 从配置文件创建客户端实例
CachedKerberosClient client = new CachedKerberosClient();

try {
    // 首次使用keytab登录并缓存ticket
    client.loginWithKeytabAndCache();
    
    // 执行操作
    client.doAs(() -> {
        // 执行需要认证的操作
        return null;
    });
    
    client.logout();
    
    // 后续可以直接使用缓存的ticket
    client.loginWithCache();
    
    // 继续执行操作
    client.doAs(() -> {
        // 执行需要认证的操作
        return null;
    });
    
    client.logout();
} catch (LoginException e) {
    e.printStackTrace();
}
```

#### 3.2 手动配置

```java
// 手动创建带缓存的客户端实例
CachedKerberosClient client = new CachedKerberosClient(
    "user@REALM.COM",
    "/path/to/user.keytab",
    "/etc/krb5.conf",
    "/tmp/krb5cc_" + System.getProperty("user.name")
);

try {
    // 使用方法同上
    ...
} catch (LoginException e) {
    e.printStackTrace();
}
```

## 注意事项

1. 确保系统上已正确安装和配置了Kerberos客户端
2. keytab文件需要妥善保管，避免泄露
3. 建议在生产环境中使用缓存机制，减少对keytab文件的访问
4. 在多线程环境中，建议为每个线程创建独立的客户端实例
5. 推荐使用配置文件方式创建客户端，便于统一管理配置

## 系统要求

- Java 8 或更高版本
- 系统已安装Kerberos客户端
- 有效的Kerberos配置（krb5.conf）
- 有效的keytab文件 