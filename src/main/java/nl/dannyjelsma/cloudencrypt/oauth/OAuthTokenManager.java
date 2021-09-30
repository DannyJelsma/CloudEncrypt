package nl.dannyjelsma.cloudencrypt.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.goterl.lazysodium.LazySodiumJava;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;
import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;
import nl.dannyjelsma.cloudencrypt.decryption.symmetric.SymmetricDecryptor;
import nl.dannyjelsma.cloudencrypt.encryption.symmetric.SymmetricEncryptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;

public class OAuthTokenManager {

    private final BackupFolder folder;
    private final File tokenFile;
    private OAuthTokens tokens;
    private SecureRandom random;

    public OAuthTokenManager(BackupFolder folder) {
        tokenFile = new File(folder.getFolder(), "oauth.json");
        this.folder = folder;
        try {
            this.random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if (!tokenFile.exists()) {
            try {
                tokenFile.createNewFile();
                tokens = new OAuthTokens();
                saveTokens();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

        loadTokens();
    }

    public void addToken(OAuthToken token) {
        tokens.addToken(token);
        saveTokens();
    }

    public void removeToken(String site) {
        List<OAuthToken> tokenList = tokens.getTokens();

        for (OAuthToken token : tokenList) {
            if (token.getSite().equals(site)) {
                tokens.removeToken(token);
                saveTokens();
                break;
            }
        }
    }

    public void replaceToken(OAuthToken token) {
        removeToken(token.getSite());
        addToken(token);
        saveTokens();
    }

    public void saveTokens() {
        ObjectMapper objectMapper = new ObjectMapper();
        LazySodiumJava sodium = CloudEncrypt.getSodium();

        try {
            SymmetricEncryptor encryptor = folder.getSymmetricEncryptor();
            byte[] jsonBytes = objectMapper.writeValueAsBytes(tokens);
            byte[] salt = new byte[16];
            byte[] encryptedBytes = encryptor.encryptBytes(jsonBytes, sodium.bytes(this.folder.getPassword()), salt);

            System.out.println(sodium.str(jsonBytes));

            try (FileOutputStream fos = new FileOutputStream(tokenFile)) {
                fos.write(salt);
                fos.write(encryptedBytes);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void loadTokens() {
        ObjectMapper objectMapper = new ObjectMapper();
        LazySodiumJava sodium = CloudEncrypt.getSodium();

        try (FileInputStream fis = new FileInputStream(tokenFile)) {
            SymmetricDecryptor decryptor = folder.getSymmetricDecryptor();
            byte[] salt = fis.readNBytes(16);
            byte[] encryptedBytes = fis.readAllBytes();
            byte[] decrypted = decryptor.decryptBytes(encryptedBytes, sodium.bytes(this.folder.getPassword()), salt);
            tokens = objectMapper.readValue(decrypted, OAuthTokens.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public boolean hasToken(String site) {
        List<OAuthToken> tokenList = tokens.getTokens();

        for (OAuthToken token : tokenList) {
            if (token.getSite().equals(site)) {
                return true;
            }
        }

        return false;
    }

    public OAuthToken getToken(String site) {
        List<OAuthToken> tokenList = tokens.getTokens();

        for (OAuthToken token : tokenList) {
            if (token.getSite().equals(site)) {
                return token;
            }
        }

        return null;
    }
}
