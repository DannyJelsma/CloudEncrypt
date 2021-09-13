package nl.dannyjelsma.cloudencrypt.upload;

import com.dropbox.core.*;
import com.dropbox.core.oauth.DbxCredential;
import com.dropbox.core.v2.DbxClientV2;
import com.dropbox.core.v2.files.*;
import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;
import nl.dannyjelsma.cloudencrypt.oauth.OAuthToken;
import nl.dannyjelsma.cloudencrypt.oauth.OAuthTokenManager;

import java.io.*;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

public class DropboxUploader implements Uploader {

    private static final int CHUNK_SIZE = 52428800;
    private DbxClientV2 client;
    private long backupTime;
    private boolean isFirstFile;

    @Override
    public String getName() {
        return "Dropbox";
    }

    @Override
    public void uploadFile(BackupFolder folder, File originalFile, File encryptedFile, String fileName) {
        if (client == null) {
            initializeClient(folder);
            backupTime = System.currentTimeMillis();
            isFirstFile = true;
        }

        try {
            String[] fileNameSplit = fileName.split("/");

            try {
                client.files().createFolderV2("/" + backupTime + fileName
                        .replace("/" + fileNameSplit[fileNameSplit.length - 1], ""));
            } catch (Exception ignore) {
            }

            if (isFirstFile) {
                removeRedundantBackups();
                isFirstFile = false;
            }

            try (BufferedInputStream fis = new BufferedInputStream(new FileInputStream(encryptedFile), CHUNK_SIZE * 3)) {
                byte[] bufIn = new byte[CHUNK_SIZE];
                UploadSessionStartUploader uploadSession = client.files().uploadSessionStart();
                OutputStream out = uploadSession.getOutputStream();

                int read;
                while ((read = fis.read(bufIn)) > 0) {
                    if (read < CHUNK_SIZE) {
                        bufIn = Arrays.copyOf(bufIn, read);
                    }

                    out.write(bufIn);
                }

                String sessionId = uploadSession.uploadAndFinish(fis).getSessionId();
                UploadSessionCursor cursor = new UploadSessionCursor(sessionId, encryptedFile.length());
                String backupPath = "/" + backupTime + fileName;
                CommitInfo info = CommitInfo.newBuilder(backupPath).withClientModified(new Date(originalFile.lastModified())).build();
                client.files().uploadSessionFinish(cursor, info).finish();
            }
        } catch (DbxException | IOException e) {
            e.printStackTrace();
            encryptedFile.delete();
        }

        encryptedFile.delete();
    }

    private void removeRedundantBackups() throws DbxException {
        // Get from config
        int max_backups = 3;
        int num_backups = 0;
        long oldest = Long.MAX_VALUE;
        ListFolderResult result = client.files().listFolder("");

        do {
            for (Metadata metadata : result.getEntries()) {
                String name = metadata.getName();
                long age;

                try {
                    age = Long.parseLong(name);
                } catch (Exception ex) {
                    continue;
                }

                num_backups += 1;

                if (age < oldest) {
                    oldest = age;
                }

                if (num_backups > max_backups) {
                    client.files().deleteV2("/" + oldest);
                    num_backups -= 1;
                }
            }

            result = client.files().listFolderContinue(result.getCursor());
        } while (result.getHasMore());
    }

    private void initializeClient(BackupFolder folder) {
        OAuthTokenManager tokenManager = folder.getTokenManager();
        DbxRequestConfig config = DbxRequestConfig.newBuilder("CloudEncryptJava/1.0.0-SNAPSHOT").build();

        if (!tokenManager.hasToken(getName())) {
            DbxPKCEWebAuth webAuth = new DbxPKCEWebAuth(config, new DbxAppInfo("em3ixac89mbj1cq"));
            DbxWebAuth.Request authRequest = DbxWebAuth.newRequestBuilder().withNoRedirect().withTokenAccessType(TokenAccessType.OFFLINE).build();
            String url = webAuth.authorize(authRequest);

            System.out.println("Go to the following url:\n" + url + "\nAfter authorizing, enter the generated code here: ");
            Scanner scanner = new Scanner(System.in);
            String code = scanner.nextLine();
            DbxAuthFinish authFinish;

            try {
                authFinish = webAuth.finishFromCode(code);
            } catch (DbxException e) {
                System.out.println("Invalid code!");
                System.exit(1);
                return;
            }

            client = new DbxClientV2(config, authFinish.getAccessToken());
            tokenManager.addToken(new OAuthToken(getName(), authFinish.getRefreshToken()));
        } else {
            String refreshToken = tokenManager.getToken(getName()).getRefreshToken();
            DbxCredential credential = new DbxCredential("", 0L, refreshToken, "em3ixac89mbj1cq");
            try {
                credential.refresh(config);
                client = new DbxClientV2(config, credential.getAccessToken());
            } catch (DbxException e) {
                e.printStackTrace();
            }
        }
    }
}
