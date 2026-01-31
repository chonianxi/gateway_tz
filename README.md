# Gateway 网络探针服务

## 概述

本模块为APP端提供网络探针数据上报功能，用于监控APP到服务端的网络质量、DNS解析情况等。

## 功能特性

- **Token管理**: 30分钟有效期，同一Token 5分钟内最多100次请求
- **防重放攻击**: Nonce + 时间戳双重校验
- **IP限流**: 每IP每3分钟最多100次（可配置）
- **AES加密**: 请求/响应报文AES-256-CBC加密
- **HMAC签名**: 防篡改校验
- **功能开关**: 支持动态关闭各接口
- **动态配置**: 配置更新后自动生效，无需重启服务
- **域名分类**: 支持按用途分类管理探测域名

## API接口概览

| 接口 | 方法 | URL | 说明 |
|------|------|-----|------|
| 获取Token | POST | `/api/probe/{ios\|android}/token` | AES加密 |
| DNS配置 | GET | `/api/probe/{ios\|android}/dns-config` | 需Token |
| 上报(APP) | POST | `/api/probe/{ios\|android}/upload` | 完整校验 |
| 上报(H5) | POST | `/api/probe/h5/upload` | 仅IP限流 |

---

### 1. 获取Token

用于APP获取探针上报所需的Token。

| 平台 | URL |
|------|-----|
| iOS | `POST /api/probe/ios/token` |
| Android | `POST /api/probe/android/token` |

#### 请求报文

**Headers:**
```
Content-Type: application/json
```

**Body (AES加密前的明文):**
```json
{
    "deviceId": "设备唯一标识",
    "appVersion": "1.0.0",
    "ts": 1706598000000
}
```

**Body (实际发送 - AES加密后的Base64):**
```
IV(16字节) + AES密文 -> Base64编码
例: "dGhpcyBpcyBhIHRlc3QgZW5jcnlwdGVkIGRhdGE..."
```

#### 响应报文

**成功响应 (HTTP 200):**

响应体为AES加密后的Base64字符串，解密后:
```json
{
    "token": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    "expiresIn": 1800
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| token | String | 探针Token，后续请求需携带 |
| expiresIn | Long | 过期时间(秒)，默认1800秒(30分钟) |

**失败响应:**
- `204 No Content` - 请求被拒绝（限流/解密失败/参数错误）
- `410 Gone` - 接口已关闭

---

### 2. 获取DNS配置

获取需要探测的域名和DNS服务器列表。

| 平台 | URL |
|------|-----|
| iOS | `GET /api/probe/ios/dns-config` |
| Android | `GET /api/probe/android/dns-config` |

#### 请求报文

**Headers:**
```
X-Probe-Token: <从Token接口获取的token>
```

#### 响应报文

**成功响应 (HTTP 200):**

响应体为AES加密后的Base64字符串，解密后:
```json
{
    "categories": [
        {
            "categoryKey": "api",
            "name": "API服务",
            "description": "核心API接口服务器",
            "domains": [
                "api.example.com",
                "api-backup.example.com"
            ]
        },
        {
            "categoryKey": "cdn",
            "name": "CDN服务",
            "description": "静态资源CDN节点",
            "domains": [
                "cdn1.example.com",
                "cdn2.example.com"
            ]
        },
        {
            "categoryKey": "thirdparty",
            "name": "第三方服务",
            "description": "第三方依赖服务",
            "domains": [
                "payment.thirdparty.com"
            ]
        }
    ],
    "dnsServers": [
        "8.8.8.8",
        "114.114.114.114",
        "223.5.5.5"
    ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| categories | Array | 域名分类列表 |
| categories[].categoryKey | String | 分类标识(上报时需要) |
| categories[].name | String | 分类名称 |
| categories[].description | String | 分类描述 |
| categories[].domains | String[] | 该分类下的域名列表 |
| dnsServers | String[] | 需要测试的DNS服务器列表 |

**失败响应:**
- `204 No Content` - 请求被拒绝（Token无效/限流）
- `410 Gone` - 接口已关闭

---

### 3. 探针数据上报 (iOS/Android)

上报网络探测结果数据，需完整安全校验。

| 平台 | URL |
|------|-----|
| iOS | `POST /api/probe/ios/upload` |
| Android | `POST /api/probe/android/upload` |

#### 请求报文

**Headers:**
```
Content-Type: application/json
X-Probe-Token: <从Token接口获取的token>
X-Ts: 1706598000000
X-Nonce: <32位随机字符串>
X-Sign: <HMAC签名>
```

| Header | 说明 |
|--------|------|
| X-Probe-Token | 探针Token |
| X-Ts | 请求时间戳(毫秒)，必须在5分钟内 |
| X-Nonce | 随机字符串(最长64字符)，防重放 |
| X-Sign | HMAC-SHA256签名 |

**HMAC签名计算:**
```
input = X-Ts + X-Nonce + SHA256(RequestBody)
signature = HMAC-SHA256(input, hmacSecret)
```

**Body (AES加密的探针数据，Gateway不解密直接透传):**
```
AES加密后的Base64字符串，解密后格式示例:
{
    "deviceId": "设备唯一标识",
    "platform": "ios",
    "appVersion": "1.0.0",
    "networkType": "wifi",
    "carrierName": "中国移动",
    "timestamp": 1706598000000,
    "probeResults": [
        {
            "categoryKey": "api",
            "domain": "api.example.com",
            "dnsServer": "8.8.8.8",
            "resolvedIp": "1.2.3.4",
            "dnsLatency": 50,
            "tcpLatency": 100,
            "httpLatency": 200,
            "httpStatusCode": 200,
            "errorCode": 0,
            "errorMsg": ""
        },
        {
            "categoryKey": "cdn",
            "domain": "cdn1.example.com",
            "dnsServer": "114.114.114.114",
            "resolvedIp": "5.6.7.8",
            "dnsLatency": 30,
            "tcpLatency": 80,
            "httpLatency": 150,
            "httpStatusCode": 200,
            "errorCode": 0,
            "errorMsg": ""
        }
    ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| probeResults[].categoryKey | String | **必填**，域名分类标识，与DNS配置返回的categoryKey对应 |

#### Gateway透传给下游的Header

| Header | 说明 |
|--------|------|
| X-Probe-Validated | 固定值 `true`，表示已通过Gateway校验 |
| X-Probe-Platform | 平台标识：`ios` 或 `android` |
| X-Probe-Client-IP | 客户端真实IP地址 |

#### 响应报文

**成功响应:**
- 由后端 `uploadlog-service` 返回

**失败响应 (Gateway层拦截):**
- `204 No Content` - 校验失败（时间戳过期/Nonce重复/HMAC错误/Token无效）
- `410 Gone` - 接口已关闭

---

### 4. H5探针数据上报 (简化版)

H5端探针上报，仅做IP限流和报文大小校验，**无需Token/HMAC/AES**。

| 平台 | URL |
|------|-----|
| H5 | `POST /api/probe/h5/upload` |

#### 请求报文

**Headers:**
```
Content-Type: application/json
```

**Body (明文JSON，无需加密):**
```json
{
    "deviceId": "浏览器指纹或会话ID",
    "platform": "h5",
    "appVersion": "1.0.0",
    "userAgent": "Mozilla/5.0...",
    "networkType": "4g",
    "timestamp": 1706598000000,
    "probeResults": [
        {
            "categoryKey": "api",
            "domain": "api.example.com",
            "dnsLatency": 50,
            "tcpLatency": 100,
            "httpLatency": 200,
            "httpStatusCode": 200,
            "errorCode": 0,
            "errorMsg": ""
        }
    ]
}
```

#### Gateway透传给下游的Header

| Header | 值 |
|--------|-----|
| X-Probe-Validated | `true` |
| X-Probe-Platform | `h5` |
| X-Probe-Client-IP | 客户端真实IP |

#### 响应报文

**成功响应:**
- 由后端 `uploadlog-service` 返回

**失败响应:**
- `204 No Content` - IP限流或报文过大(>64KB)
- `410 Gone` - 接口已关闭

#### 安全说明

| 项目 | iOS/Android | H5 |
|------|-------------|-----|
| Token验证 | ✅ | ❌ |
| HMAC签名 | ✅ | ❌ |
| AES加密 | ✅ | ❌ |
| Nonce防重放 | ✅ | ❌ |
| IP限流 | ✅ | ✅ |
| 报文大小限制 | ✅ | ✅ |

> **注意**: H5接口安全性较低，建议仅用于非敏感的网络质量采集，不要传输用户隐私数据。

---

## 安全机制

### 校验顺序 (仅在Gateway层执行)

```
1. IP限流检查 (每IP每3分钟100次)
2. 时间戳校验 (必须在5分钟内)
3. Header长度校验 (防止超长攻击)
4. Token验证 (Redis中存在且未超限)
5. Token IP绑定校验 (必须与申请Token时的IP一致)
6. Nonce防重放 (原子SETNX操作)
7. HMAC签名验证
```

**任何一步失败直接返回204，不暴露具体错误原因。**

### 防护措施

| 攻击类型 | 防护机制 |
|----------|----------|
| **内存耗尽(OOM)** | 请求体最大64KB，Header长度限制，密文最大1MB |
| **重放攻击** | Nonce原子SETNX+本地LRU缓存双重校验 |
| **时序攻击** | HMAC使用`MessageDigest.isEqual`常量时间比较 |
| **IP伪造** | IP格式校验，优先使用X-Real-IP |
| **Token盗用** | Token绑定IP，不同IP无法使用 |
| **限流绕过** | Redis异常时拒绝请求(fail-closed) |
| **并发竞态** | Nonce使用Redis SETNX原子操作 |
| **配置竞态** | 动态配置读取时复制Map防止并发修改 |
| **密钥缓存泄露** | AES密钥缓存最夙10个，超出清空 |

### 加密说明

| 项目 | 算法 | 说明 |
|------|------|------|
| 对称加密 | AES-256-CBC | PKCS5Padding，IV随机生成前置于密文 |
| 密钥派生 | PBKDF2-HMAC-SHA256 | 65536次迭代 |
| 签名 | HMAC-SHA256 | 用于上报接口防篡改 |
| 哈希 | SHA-256 | 计算Body哈希 |

---

## 配置说明

```yaml
probe:
  # 总开关
  enabled: true
  
  # 各接口独立开关
  token-enabled: true
  dns-config-enabled: true
  upload-enabled: true
  h5-upload-enabled: true           # H5上报开关
  
  # 密钥配置 (生产环境请修改!)
  aes-key: your-aes-key-here
  hmac-secret: your-hmac-secret-here
  
  # Token配置
  token-ttl-minutes: 30              # Token有效期
  token-max-requests-per-window: 100 # 同一Token在窗口期内最大请求数
  token-request-window-minutes: 5    # Token请求窗口期
  
  # 时间戳校验
  timestamp-valid-minutes: 5         # 时间戳有效范围
  
  # IP限流
  ip-rate-limit-count: 100           # 每IP最大请求数
  ip-rate-limit-window-seconds: 180  # 限流窗口(秒)
  
  # Nonce缓存
  nonce-cache-size: 100000           # 本地LRU缓存大小
  nonce-cache-expire-minutes: 10     # Nonce过期时间
  
  # 域名分类配置 (支持动态刷新，修改后自动生效)
  domain-categories:
    api:                              # 分类标识Key
      name: "API服务"                  # 分类名称
      description: "核心API接口服务器"  # 分类描述
      domains:                        # 该分类下的域名列表
        - api.example.com
        - api-backup.example.com
    cdn:
      name: "CDN服务"
      description: "静态资源CDN节点"
      domains:
        - cdn1.example.com
        - cdn2.example.com
        - cdn3.example.com
    static:
      name: "静态资源"
      description: "静态文件服务器"
      domains:
        - static.example.com
        - img.example.com
    thirdparty:
      name: "第三方服务"
      description: "第三方依赖服务"
      domains:
        - payment.thirdparty.com
        - push.thirdparty.com
  
  # DNS服务器配置 (支持动态刷新)
  probe-dns-servers:
    - 8.8.8.8
    - 114.114.114.114
    - 223.5.5.5

  # 路径配置
  paths:
    ios-token-path: /api/probe/ios/token
    android-token-path: /api/probe/android/token
    ios-dns-config-path: /api/probe/ios/dns-config
    android-dns-config-path: /api/probe/android/dns-config
    ios-upload-path: /api/probe/ios/upload
    android-upload-path: /api/probe/android/upload
    h5-upload-path: /api/probe/h5/upload
```

### 动态配置刷新

所有配置项支持动态刷新，无需重启服务：

1. **Spring Cloud Config**: 通过配置中心修改后自动推送
2. **Nacos**: 支持Nacos配置中心实时更新
3. **手动刷新**: 调用 `/actuator/refresh` 端点触发刷新

```bash
# 手动触发配置刷新
curl -X POST http://localhost:8080/actuator/refresh
```

**注意**: 需要在 `pom.xml` 中添加 actuator 依赖并开启 refresh 端点：
```yaml
management:
  endpoints:
    web:
      exposure:
        include: refresh
```

---

## APP端集成指南

### 加密参数说明 (必须与Gateway一致)

| 参数 | 值 | 说明 |
|------|-----|------|
| 算法 | AES/CBC/PKCS5Padding | 对称加密 |
| 密钥派生 | PBKDF2WithHmacSHA256 | 从密码派生密钥 |
| SALT | `ProbeAesSalt2024` | 固定盐值 |
| 迭代次数 | 65536 | PBKDF2迭代 |
| 密钥长度 | 256位 (32字节) | AES-256 |
| IV长度 | 16字节 | 随机生成，前置于密文 |

### iOS Swift 示例

#### AESUtil.swift (完整实现)

```swift
import Foundation
import CommonCrypto

class AESUtil {
    private static let salt = "ProbeAesSalt2024".data(using: .utf8)!
    private static let iterationCount: UInt32 = 65536
    private static let keyLength = 32  // 256 bits
    private static let ivLength = 16
    
    /// PBKDF2密钥派生 - 必须与Gateway一致
    private static func deriveKey(password: String) -> Data {
        let passwordData = password.data(using: .utf8)!
        var derivedKey = [UInt8](repeating: 0, count: keyLength)
        
        passwordData.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                    passwordData.count,
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterationCount,
                    &derivedKey,
                    keyLength
                )
            }
        }
        return Data(derivedKey)
    }
    
    /// AES加密 - IV随机生成并前置于密文
    static func encrypt(plainText: String, key: String) -> String? {
        guard let data = plainText.data(using: .utf8) else { return nil }
        return encrypt(data: data, key: key)
    }
    
    static func encrypt(data: Data, key: String) -> String? {
        let derivedKey = deriveKey(password: key)
        
        // 生成随机IV
        var iv = [UInt8](repeating: 0, count: ivLength)
        guard SecRandomCopyBytes(kSecRandomDefault, ivLength, &iv) == errSecSuccess else {
            return nil
        }
        
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var numBytesEncrypted: size_t = 0
        
        let status = derivedKey.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionPKCS7Padding),
                    keyBytes.baseAddress, keyLength,
                    iv,
                    dataBytes.baseAddress, data.count,
                    &buffer, bufferSize,
                    &numBytesEncrypted
                )
            }
        }
        
        guard status == kCCSuccess else { return nil }
        
        // IV + 密文
        var combined = Data(iv)
        combined.append(contentsOf: buffer.prefix(numBytesEncrypted))
        
        return combined.base64EncodedString()
    }
    
    /// AES解密 - 从密文前16字节提取IV
    static func decrypt(base64String: String, key: String) -> Data? {
        guard let combined = Data(base64Encoded: base64String),
              combined.count > ivLength else { return nil }
        
        let derivedKey = deriveKey(password: key)
        let iv = combined.prefix(ivLength)
        let encrypted = combined.suffix(from: ivLength)
        
        let bufferSize = encrypted.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var numBytesDecrypted: size_t = 0
        
        let status = derivedKey.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                encrypted.withUnsafeBytes { dataBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress, keyLength,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, encrypted.count,
                        &buffer, bufferSize,
                        &numBytesDecrypted
                    )
                }
            }
        }
        
        guard status == kCCSuccess else { return nil }
        return Data(buffer.prefix(numBytesDecrypted))
    }
    
    static func decryptToString(base64String: String, key: String) -> String? {
        guard let data = decrypt(base64String: base64String, key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
```

#### HMACUtil.swift

```swift
import Foundation
import CommonCrypto

class HMACUtil {
    /// HMAC-SHA256签名
    static func sign(input: String, secret: String) -> String {
        let key = secret.data(using: .utf8)!
        let data = input.data(using: .utf8)!
        
        var hmac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { dataBytes in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA256),
                    keyBytes.baseAddress, key.count,
                    dataBytes.baseAddress, data.count,
                    &hmac
                )
            }
        }
        
        return hmac.map { String(format: "%02x", $0) }.joined()
    }
}

extension Data {
    func sha256Hex() -> String {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
```

#### ProbeClient.swift (使用示例)

```swift
class ProbeClient {
    private let aesKey = "your-aes-key-here"  // 与Gateway配置一致
    private let hmacSecret = "your-hmac-secret-here"
    private var token: String?
    
    func fetchToken(deviceId: String) async throws -> String {
        let request = ["deviceId": deviceId, "appVersion": "1.0.0", "ts": Int64(Date().timeIntervalSince1970 * 1000)] as [String : Any]
        let jsonData = try JSONSerialization.data(withJSONObject: request)
        
        guard let encryptedBody = AESUtil.encrypt(data: jsonData, key: aesKey) else {
            throw ProbeError.encryptionFailed
        }
        
        var urlRequest = URLRequest(url: URL(string: "https://api.example.com/api/probe/ios/token")!)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.httpBody = encryptedBody.data(using: .utf8)
        
        let (data, _) = try await URLSession.shared.data(for: urlRequest)
        
        guard let responseStr = String(data: data, encoding: .utf8),
              let decryptedData = AESUtil.decrypt(base64String: responseStr, key: aesKey),
              let json = try? JSONSerialization.jsonObject(with: decryptedData) as? [String: Any],
              let token = json["token"] as? String else {
            throw ProbeError.decryptionFailed
        }
        
        self.token = token
        return token
    }
    
    func uploadProbeData(probeData: [String: Any]) async throws {
        guard let token = self.token else { throw ProbeError.noToken }
        
        let jsonData = try JSONSerialization.data(withJSONObject: probeData)
        guard let encryptedBody = AESUtil.encrypt(data: jsonData, key: aesKey) else { return }
        
        let bodyData = encryptedBody.data(using: .utf8)!
        let ts = String(Int64(Date().timeIntervalSince1970 * 1000))
        let nonce = UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let bodyHash = bodyData.sha256Hex()
        let sign = HMACUtil.sign(input: ts + nonce + bodyHash, secret: hmacSecret)
        
        var urlRequest = URLRequest(url: URL(string: "https://api.example.com/api/probe/ios/upload")!)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue(token, forHTTPHeaderField: "X-Probe-Token")
        urlRequest.setValue(ts, forHTTPHeaderField: "X-Ts")
        urlRequest.setValue(nonce, forHTTPHeaderField: "X-Nonce")
        urlRequest.setValue(sign, forHTTPHeaderField: "X-Sign")
        urlRequest.httpBody = bodyData
        
        _ = try? await URLSession.shared.data(for: urlRequest)
    }
}
```

### Android Kotlin 示例

#### AesUtil.kt (完整实现)

```kotlin
import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

object AesUtil {
    private const val ALGORITHM = "AES"
    private const val TRANSFORMATION = "AES/CBC/PKCS5Padding"
    private const val IV_LENGTH = 16
    private const val KEY_LENGTH = 256
    private const val ITERATION_COUNT = 65536
    private val SALT = "ProbeAesSalt2024".toByteArray(Charsets.UTF_8)

    /**
     * PBKDF2密钥派生 - 必须与Gateway一致
     */
    private fun deriveKey(password: String): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), SALT, ITERATION_COUNT, KEY_LENGTH)
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, ALGORITHM)
    }

    /**
     * AES加密 - IV随机生成并前置于密文
     */
    fun encrypt(plainText: String, key: String): String {
        val secretKey = deriveKey(key)
        
        // 生成随机IV
        val iv = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(iv)
        val ivSpec = IvParameterSpec(iv)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
        val encrypted = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        // IV + 密文
        val combined = ByteArray(IV_LENGTH + encrypted.size)
        System.arraycopy(iv, 0, combined, 0, IV_LENGTH)
        System.arraycopy(encrypted, 0, combined, IV_LENGTH, encrypted.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * AES解密 - 从密文前16字节提取IV
     */
    fun decrypt(cipherText: String, key: String): String {
        val combined = Base64.decode(cipherText, Base64.NO_WRAP)
        require(combined.size > IV_LENGTH) { "Invalid cipher text" }

        val iv = combined.copyOfRange(0, IV_LENGTH)
        val encrypted = combined.copyOfRange(IV_LENGTH, combined.size)

        val secretKey = deriveKey(key)
        val ivSpec = IvParameterSpec(iv)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        val decrypted = cipher.doFinal(encrypted)

        return String(decrypted, Charsets.UTF_8)
    }
}
```

#### HmacUtil.kt

```kotlin
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

object HmacUtil {
    /**
     * HMAC-SHA256签名
     */
    fun sign(input: String, secret: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        val hash = mac.doFinal(input.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }
}

fun ByteArray.sha256Hex(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(this)
    return hash.joinToString("") { "%02x".format(it) }
}
```

#### ProbeClient.kt (使用示例)

```kotlin
class ProbeClient(private val context: Context) {
    private val aesKey = "your-aes-key-here"  // 与Gateway配置一致
    private val hmacSecret = "your-hmac-secret-here"
    private var token: String? = null
    
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    suspend fun fetchToken(): String = withContext(Dispatchers.IO) {
        val request = mapOf(
            "deviceId" to getDeviceId(),
            "appVersion" to BuildConfig.VERSION_NAME,
            "ts" to System.currentTimeMillis()
        )
        
        val json = Gson().toJson(request)
        val encryptedBody = AesUtil.encrypt(json, aesKey)
        
        val httpRequest = Request.Builder()
            .url("https://api.example.com/api/probe/android/token")
            .post(encryptedBody.toRequestBody("application/json".toMediaType()))
            .build()
        
        val response = client.newCall(httpRequest).execute()
        if (response.code != 200) throw Exception("Token fetch failed")
        
        val decryptedBody = AesUtil.decrypt(response.body?.string() ?: "", aesKey)
        val tokenResponse = Gson().fromJson(decryptedBody, TokenResponse::class.java)
        
        token = tokenResponse.token
        tokenResponse.token
    }

    suspend fun uploadProbeData(probeData: ProbeData) = withContext(Dispatchers.IO) {
        val currentToken = token ?: return@withContext
        
        val json = Gson().toJson(probeData)
        val encryptedBody = AesUtil.encrypt(json, aesKey)
        val bodyBytes = encryptedBody.toByteArray()
        
        val ts = System.currentTimeMillis().toString()
        val nonce = UUID.randomUUID().toString().replace("-", "")
        val bodyHash = bodyBytes.sha256Hex()
        val sign = HmacUtil.sign(ts + nonce + bodyHash, hmacSecret)
        
        val httpRequest = Request.Builder()
            .url("https://api.example.com/api/probe/android/upload")
            .header("X-Probe-Token", currentToken)
            .header("X-Ts", ts)
            .header("X-Nonce", nonce)
            .header("X-Sign", sign)
            .post(encryptedBody.toRequestBody("application/json".toMediaType()))
            .build()
        
        try {
            client.newCall(httpRequest).execute()
        } catch (e: Exception) {
            // 静默失败
        }
    }
}

### H5 JavaScript 示例

```javascript
class ProbeClient {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
    }

    // H5探针上报 - 无需加密，直接发送明文JSON
    async uploadProbeData(probeData) {
        const data = {
            deviceId: this.getDeviceFingerprint(),
            platform: 'h5',
            appVersion: '1.0.0',
            userAgent: navigator.userAgent,
            networkType: this.getNetworkType(),
            timestamp: Date.now(),
            probeResults: probeData
        };

        try {
            const response = await fetch(`${this.baseUrl}/api/probe/h5/upload`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            // 静默处理，不影响页面功能
            return response.ok;
        } catch (error) {
            // 静默失败
            console.debug('Probe upload failed:', error);
            return false;
        }
    }

    // 执行网络探测
    async probe(domains) {
        const results = [];
        
        for (const domain of domains) {
            const startTime = performance.now();
            try {
                const response = await fetch(`https://${domain}/health`, {
                    method: 'HEAD',
                    mode: 'no-cors'
                });
                const latency = Math.round(performance.now() - startTime);
                
                results.push({
                    categoryKey: domain.categoryKey || 'default',
                    domain: domain.host || domain,
                    httpLatency: latency,
                    httpStatusCode: 200,
                    errorCode: 0,
                    errorMsg: ''
                });
            } catch (error) {
                results.push({
                    categoryKey: domain.categoryKey || 'default',
                    domain: domain.host || domain,
                    httpLatency: -1,
                    httpStatusCode: 0,
                    errorCode: -1,
                    errorMsg: error.message
                });
            }
        }
        
        return this.uploadProbeData(results);
    }

    getDeviceFingerprint() {
        // 简单指纹，生产环境建议使用fingerprintjs
        return btoa(navigator.userAgent + screen.width + screen.height).slice(0, 32);
    }

    getNetworkType() {
        const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        return conn?.effectiveType || 'unknown';
    }
}

// 使用示例
const probeClient = new ProbeClient('https://api.example.com');
probeClient.probe([
    { host: 'api.example.com', categoryKey: 'api' },
    { host: 'cdn.example.com', categoryKey: 'cdn' }
]);
```

---

## 错误处理

各端需要对以下HTTP状态码做兼容处理:

| 状态码 | 含义 | APP处理建议 |
|--------|------|-------------|
| 200 | 成功 | 正常处理 |
| 204 | 请求被拒绝 | 静默忽略，不重试 |
| 410 | 接口已关闭 | 停止探针功能 |
| 其他 | 服务异常 | 静默忽略，稍后重试 |

---

## 架构图

```
┌─────────────┐     AES加密请求      ┌─────────────────────┐
│   iOS APP   │ ──────────────────▶ │                     │
└─────────────┘                      │      Gateway        │
                                     │                     │
┌─────────────┐     AES加密请求      │  iOS/Android:       │
│ Android APP │ ──────────────────▶ │  - IP限流           │
└─────────────┘                      │  - 校验ts/nonce/HMAC │
                                     │  - Token验证         │
┌─────────────┐     明文JSON请求      │                     │
│   H5 Web    │ ──────────────────▶ │  H5:                │
└─────────────┘                      │  - 仅IP限流          │
                                     │  - 报文大小限制       │
                                     └──────────┬──────────┘
                                                │ 透传
                                                ▼
                                     ┌─────────────────────┐
                                     │    Uploadlog        │
                                     │      Service        │
                                     │                     │
                                     │  - AES解密(APP)      │
                                     │  - 直接处理(H5)       │
                                     │  - 发送Kafka         │
                                     └─────────────────────┘
```

---

## 下游服务集成指南

### 获取客户端真实IP

Gateway会在透传请求时添加以下Header，下游服务可直接读取：

```java
@RestController
@RequestMapping("/api/probe")
public class ProbeUploadController {

    @PostMapping("/{platform}/upload")
    public ResponseEntity<?> handleUpload(
            @PathVariable String platform,
            @RequestHeader("X-Probe-Client-IP") String clientIp,
            @RequestHeader("X-Probe-Platform") String probePlatform,
            @RequestHeader(value = "X-Probe-Validated", defaultValue = "false") String validated,
            @RequestBody String encryptedBody) {
        
        // clientIp 即为客户端真实IP
        log.info("Received probe data from IP: {}, platform: {}", clientIp, probePlatform);
        
        // 根据平台类型处理
        if ("h5".equals(probePlatform)) {
            // H5: 明文JSON，直接解析
            ProbeUploadData data = JSON.parseObject(encryptedBody, ProbeUploadData.class);
            processProbeData(data, clientIp);
        } else {
            // iOS/Android: 需要AES解密
            String decryptedJson = AesUtil.decrypt(encryptedBody, aesKey);
            ProbeUploadData data = JSON.parseObject(decryptedJson, ProbeUploadData.class);
            processProbeData(data, clientIp);
        }
        
        return ResponseEntity.ok().build();
    }
}
```

### AES解密示例 (Java)

iOS/Android上报的数据是AES加密的，下游服务需要解密：

```java
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

public class AesUtil {
    
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final byte[] SALT = "ProbeAesSalt2024".getBytes(StandardCharsets.UTF_8);

    /**
     * AES解密
     * @param cipherText Base64编码的密文 (前16字节为IV)
     * @param key 密钥 (与Gateway配置的aes-key一致)
     * @return 解密后的明文JSON
     */
    public static String decrypt(String cipherText, String key) {
        try {
            byte[] combined = Base64.getDecoder().decode(cipherText);
            
            // 前16字节为IV
            byte[] iv = new byte[IV_LENGTH];
            byte[] encrypted = new byte[combined.length - IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
            System.arraycopy(combined, IV_LENGTH, encrypted, 0, encrypted.length);

            SecretKeySpec secretKey = deriveKey(key);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("AES decryption failed", e);
        }
    }

    /**
     * 密钥派生 (PBKDF2)
     * 必须与Gateway使用相同的派生参数
     */
    private static SecretKeySpec deriveKey(String key) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(key.toCharArray(), SALT, ITERATION_COUNT, KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
}
```

### 处理逻辑对比

| 平台 | X-Probe-Platform | Body格式 | 解密 |
|------|------------------|----------|------|
| iOS | `ios` | AES加密Base64 | **需要** |
| Android | `android` | AES加密Base64 | **需要** |
| H5 | `h5` | 明文JSON | **不需要** |

### 完整处理流程

```java
@Service
public class ProbeDataService {

    @Value("${probe.aes-key}")
    private String aesKey;

    public void processUpload(String platform, String clientIp, String body) {
        ProbeUploadData data;
        
        if ("h5".equals(platform)) {
            // H5: 直接解析明文JSON
            data = JSON.parseObject(body, ProbeUploadData.class);
        } else {
            // iOS/Android: 先解密再解析
            String decryptedJson = AesUtil.decrypt(body, aesKey);
            data = JSON.parseObject(decryptedJson, ProbeUploadData.class);
        }
        
        // 补充客户端IP
        data.setClientIp(clientIp);
        
        // 发送到Kafka
        kafkaTemplate.send("probe-data-topic", JSON.toJSONString(data));
    }
}
```

---

## Redis Key说明

| Key Pattern | 用途 | TTL |
|-------------|------|-----|
| `probe:token:{token}` | Token信息存储 | 30分钟 |
| `probe:token:count:{token}` | Token请求计数 | 5分钟 |
| `probe:nonce:{nonce}` | Nonce防重放 | 10分钟 |
| `probe:ip:limit:{type}:{ip}` | IP限流计数 | 3分钟 |

---

## 注意事项

1. **密钥安全**: `aes-key` 和 `hmac-secret` 必须安全存储，APP端存放在沙盒/Keychain中
2. **时钟同步**: APP设备时间与服务器时间差异不能超过5分钟
3. **Nonce唯一性**: 每次请求必须使用新的Nonce
4. **Token刷新**: Token过期前应主动刷新，避免上报失败
5. **静默失败**: 探针功能失败不应影响APP正常使用
