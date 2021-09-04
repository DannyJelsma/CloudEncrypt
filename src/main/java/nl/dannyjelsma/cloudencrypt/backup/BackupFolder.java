package nl.dannyjelsma.cloudencrypt.backup;

import java.io.File;

public class BackupFolder {

    private final File folder;
    private final File privateKey;
    private final File publicKey;

    public BackupFolder(File folder) {
        this.folder = folder;
        this.privateKey = new File(folder, "ce_priv.key");
        this.publicKey = new File(folder, "ce_pub.key");
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
}
