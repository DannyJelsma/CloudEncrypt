package nl.dannyjelsma.cloudencrypt.backup;

import nl.dannyjelsma.cloudencrypt.decryption.symmetric.AESDecryptor;
import nl.dannyjelsma.cloudencrypt.decryption.symmetric.ChaChaDecryptor;
import nl.dannyjelsma.cloudencrypt.decryption.symmetric.SymmetricDecryptor;
import nl.dannyjelsma.cloudencrypt.encryption.EncryptionAlgorithm;
import nl.dannyjelsma.cloudencrypt.encryption.symmetric.AESEncryptor;
import nl.dannyjelsma.cloudencrypt.encryption.symmetric.ChaChaEncryptor;
import nl.dannyjelsma.cloudencrypt.encryption.symmetric.SymmetricEncryptor;
import nl.dannyjelsma.cloudencrypt.oauth.OAuthTokenManager;

import java.io.File;

public class BackupFolder {

    private final File folder;
    private final File privateKey;
    private final File publicKey;
    private final String password;
    private final OAuthTokenManager tokenManager;
    private final EncryptionAlgorithm algorithm;
    private final boolean encryptFileNames;
    private final boolean encryptDirectoryNames;

    public BackupFolder(File folder, String password, EncryptionAlgorithm algorithm, boolean encryptFileNames, boolean encryptDirectoryNames) {
        this.folder = folder;
        this.privateKey = new File(folder, "ce_priv.key");
        this.publicKey = new File(folder, "ce_pub.key");
        this.password = password;
        this.algorithm = algorithm;
        this.encryptFileNames = encryptFileNames;
        this.encryptDirectoryNames = encryptDirectoryNames;
        this.tokenManager = new OAuthTokenManager(this);
    }

    public String getPassword() {
        return password;
    }

    public boolean requiresFirstTimeInit() {
        return !publicKey.exists() || !privateKey.exists();
    }

    public File getPrivateKey() {
        return privateKey;
    }

    public File getPublicKey() {
        return publicKey;
    }

    public File getFolder() {
        return folder;
    }

    public OAuthTokenManager getTokenManager() {
        return tokenManager;
    }

    public SymmetricDecryptor getSymmetricDecryptor() {
        return switch (this.algorithm) {
            case AES_GCM -> new AESDecryptor();
            case XCHACHA20_POLY1305 -> new ChaChaDecryptor();
        };
    }

    public SymmetricEncryptor getSymmetricEncryptor() {
        return switch (this.algorithm) {
            case AES_GCM -> new AESEncryptor();
            case XCHACHA20_POLY1305 -> new ChaChaEncryptor();
        };
    }

    public EncryptionAlgorithm getAlgorithm() {
        return algorithm;
    }

    public boolean isEncryptFileNamesEnabled() {
        return encryptFileNames;
    }

    public boolean isEncryptDirectoryNamesEnabled() {
        return encryptDirectoryNames;
    }
}
