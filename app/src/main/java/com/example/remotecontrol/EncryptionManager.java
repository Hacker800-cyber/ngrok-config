package com.example.remotecontrol;

import android.util.Log;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import android.util.Base64;

/**
 * EncryptionManager - TLS/SSL Socket Wrapper और AES Encryption
 *
 * यह class provide करती है:
 * - TLS/SSL socket creation (secure communication)
 * - AES-256-GCM symmetric encryption (message payload)
 * - Server certificate validation helpers
 * - Key management utilities (generate, encode, decode)
 *
 * Usage:
 *   EncryptionManager em = EncryptionManager.getInstance();
 *
 *   // TLS socket बनाएं
 *   SSLSocket socket = em.createTlsSocket("myserver.com", 8443, true);
 *
 *   // Message encrypt करें
 *   String encrypted = em.encryptAesGcm("hello world", base64Key);
 *   String decrypted = em.decryptAesGcm(encrypted, base64Key);
 */
public class EncryptionManager {

    private static final String TAG = "EncryptionManager";

    // AES-GCM cipher algorithm string
    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";

    // GCM authentication tag length in bits (128 = maximum security)
    private static final int GCM_TAG_LENGTH_BITS = 128;

    // GCM IV (Initialization Vector) length in bytes
    private static final int GCM_IV_LENGTH_BYTES = 12;

    // AES key size in bits
    private static final int AES_KEY_BITS = 256;

    // Singleton instance
    private static volatile EncryptionManager instance;

    /**
     * Private constructor - singleton
     */
    private EncryptionManager() {}

    /**
     * getInstance() - thread-safe singleton accessor
     */
    public static EncryptionManager getInstance() {
        if (instance == null) {
            synchronized (EncryptionManager.class) {
                if (instance == null) {
                    instance = new EncryptionManager();
                }
            }
        }
        return instance;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TLS/SSL Socket Creation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * createTlsSocket() - TLS-enabled socket बनाएं
     *
     * @param host              Server hostname
     * @param port              Server port
     * @param validateCert      true = proper CA validation, false = trust-all (dev only)
     * @return                  Connected SSLSocket
     * @throws IOException      Connection failure
     */
    public SSLSocket createTlsSocket(String host, int port, boolean validateCert)
            throws IOException {
        try {
            SSLContext sslContext;

            if (validateCert) {
                // Production: default SSL context जो system CA store use करता है
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, null, new SecureRandom());
                Log.d(TAG, "TLS socket: using system CA validation");
            } else {
                // Development/testing: trust-all certificate (INSECURE - production में use न करें)
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, getTrustAllManagers(), new SecureRandom());
                Log.w(TAG, "WARNING: TLS socket created with trust-all (INSECURE - dev mode only)");
            }

            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(host, port);

            // Minimum TLS 1.2 enforce करें (TLS 1.0/1.1 insecure हैं)
            sslSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});

            // Secure cipher suites (weak ciphers disable)
            sslSocket.setEnabledCipherSuites(getSecureCipherSuites(sslSocket));

            // Handshake complete होने दें
            sslSocket.startHandshake();
            Log.d(TAG, "TLS handshake successful with " + host + ":" + port);

            return sslSocket;

        } catch (IOException ioe) {
            throw ioe;  // Re-throw IO exceptions as-is
        } catch (Exception e) {
            throw new IOException("TLS socket creation failed: " + e.getMessage(), e);
        }
    }

    /**
     * wrapExistingSocket() - existing socket को TLS में upgrade करें (STARTTLS pattern)
     *
     * @param existingSocket  Plain socket to wrap
     * @param host            Server hostname (for SNI)
     * @param port            Server port
     * @param validateCert    Certificate validation toggle
     */
    public SSLSocket wrapExistingSocket(Socket existingSocket, String host, int port,
                                         boolean validateCert) throws IOException {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            if (validateCert) {
                sslContext.init(null, null, new SecureRandom());
            } else {
                sslContext.init(null, getTrustAllManagers(), new SecureRandom());
            }

            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                    existingSocket, host, port, true /* autoClose */);
            sslSocket.setUseClientMode(true);
            sslSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            sslSocket.startHandshake();
            return sslSocket;

        } catch (Exception e) {
            throw new IOException("Socket TLS wrap failed: " + e.getMessage(), e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AES-256-GCM Encryption/Decryption
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * encryptAesGcm() - AES-256-GCM से message encrypt करें
     *
     * Format of returned string: Base64(IV + CipherText + AuthTag)
     * IV हर encryption में random generate होता है (security best practice)
     *
     * @param plaintext     Message to encrypt
     * @param base64Key     Base64-encoded 256-bit AES key
     * @return              Base64-encoded encrypted payload (IV prepended)
     * @throws Exception    On encryption failure
     */
    public String encryptAesGcm(String plaintext, String base64Key) throws Exception {
        if (plaintext == null) throw new IllegalArgumentException("Plaintext cannot be null");
        if (base64Key == null || base64Key.isEmpty()) {
            throw new IllegalArgumentException("Encryption key cannot be null/empty");
        }

        // Key decode करें
        byte[] keyBytes = Base64.decode(base64Key, Base64.NO_WRAP);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        // Random IV generate करें (GCM needs unique IV per encryption)
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);

        // Cipher initialize करें
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec paramSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);

        // Encrypt करें
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // IV + CipherText combine करें (IV decryption के लिए ज़रूरी है)
        byte[] ivAndCiphertext = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, iv.length);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, iv.length, ciphertext.length);

        return Base64.encodeToString(ivAndCiphertext, Base64.NO_WRAP);
    }

    /**
     * decryptAesGcm() - AES-256-GCM encrypted message को decrypt करें
     *
     * @param encryptedBase64   encryptAesGcm() से returned string
     * @param base64Key         Same Base64-encoded AES key used for encryption
     * @return                  Decrypted plaintext string
     * @throws Exception        On decryption failure (wrong key, tampered data)
     */
    public String decryptAesGcm(String encryptedBase64, String base64Key) throws Exception {
        if (encryptedBase64 == null || encryptedBase64.isEmpty()) {
            throw new IllegalArgumentException("Encrypted data cannot be null/empty");
        }
        if (base64Key == null || base64Key.isEmpty()) {
            throw new IllegalArgumentException("Decryption key cannot be null/empty");
        }

        // Base64 decode करें
        byte[] ivAndCiphertext = Base64.decode(encryptedBase64, Base64.NO_WRAP);

        if (ivAndCiphertext.length <= GCM_IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("Encrypted data is too short to be valid");
        }

        // IV और ciphertext अलग करें
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        byte[] ciphertext = new byte[ivAndCiphertext.length - GCM_IV_LENGTH_BYTES];
        System.arraycopy(ivAndCiphertext, 0, iv, 0, GCM_IV_LENGTH_BYTES);
        System.arraycopy(ivAndCiphertext, GCM_IV_LENGTH_BYTES, ciphertext, 0, ciphertext.length);

        // Key decode करें
        byte[] keyBytes = Base64.decode(base64Key, Base64.NO_WRAP);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        // Cipher initialize करें (DECRYPT mode)
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec paramSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);

        // Decrypt करें (GCM authentication tag automatically verify होता है)
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, "UTF-8");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Key Management
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * generateAesKey() - new random AES-256 key generate करें
     *
     * @return  Base64-encoded 256-bit AES key
     */
    public String generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_BITS, new SecureRandom());
        SecretKey secretKey = keyGen.generateKey();
        return Base64.encodeToString(secretKey.getEncoded(), Base64.NO_WRAP);
    }

    /**
     * encodeKeyToBase64() - raw key bytes को Base64 string में convert करें
     */
    public String encodeKeyToBase64(byte[] keyBytes) {
        return Base64.encodeToString(keyBytes, Base64.NO_WRAP);
    }

    /**
     * decodeKeyFromBase64() - Base64 string से raw key bytes निकालें
     */
    public byte[] decodeKeyFromBase64(String base64Key) {
        return Base64.decode(base64Key, Base64.NO_WRAP);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * getTrustAllManagers() - सभी certificates trust करने वाला TrustManager
     * ⚠️ केवल development/testing के लिए - production में use न करें!
     */
    private TrustManager[] getTrustAllManagers() {
        return new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {}

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {}

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
    }

    /**
     * getSecureCipherSuites() - socket से supported secure cipher suites filter करें
     * Weak ciphers (RC4, NULL, EXPORT, anon, DES) exclude करते हैं
     */
    private String[] getSecureCipherSuites(SSLSocket socket) {
        String[] supported = socket.getSupportedCipherSuites();
        java.util.List<String> secure = new java.util.ArrayList<>();
        for (String suite : supported) {
            // Weak cipher patterns को skip करें
            if (suite.contains("_NULL_") || suite.contains("_anon_")
                    || suite.contains("_EXPORT_") || suite.contains("_DES_")
                    || suite.contains("_RC4_")) {
                continue;
            }
            secure.add(suite);
        }
        return secure.toArray(new String[0]);
    }
}
