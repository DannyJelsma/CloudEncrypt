package nl.dannyjelsma.cloudencrypt.download;

import com.dropbox.core.*;
import com.dropbox.core.oauth.DbxCredential;
import com.dropbox.core.v2.DbxClientV2;
import com.dropbox.core.v2.files.FileMetadata;
import com.dropbox.core.v2.files.ListFolderResult;
import com.dropbox.core.v2.files.Metadata;
import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;
import nl.dannyjelsma.cloudencrypt.oauth.OAuthToken;
import nl.dannyjelsma.cloudencrypt.oauth.OAuthTokenManager;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class DropboxDownloader implements Downloader {

    private static final int CHUNK_SIZE = 52428800;
    private DbxClientV2 client;

    @Override
    public String getName() {
        return "Dropbox";
    }

    @Override
    public List<File> downloadFiles(BackupFolder folder, long backupTime) {
        List<File> downloadedFiles = new ArrayList<>();

        if (client == null) {
            initializeClient(folder);
        }

        try {
            if (backupTime < 0) {
                long newest = Long.MIN_VALUE;
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

                        if (age > newest) {
                            newest = age;
                        }
                    }

                    result = client.files().listFolderContinue(result.getCursor());
                } while (result.getHasMore());

                backupTime = newest;
            }

            ListFolderResult result = client.files().listFolderBuilder("/" + backupTime).withRecursive(true).withIncludeNonDownloadableFiles(false).start();

            do {
                for (Metadata metadata : result.getEntries()) {
                    String path = metadata.getPathDisplay();
                    String dstPath = metadata.getPathDisplay().replace("/" + backupTime, "");
                    File dstFile = new File(folder.getFolder(), dstPath);

                    if (!dstFile.getParentFile().exists()) {
                        dstFile.getParentFile().mkdirs();
                    }

                    System.out.println("Downloading " + dstPath + "...");
                    long start = System.currentTimeMillis();
                    try (DbxDownloader<FileMetadata> downloader = client.files().download(path); FileOutputStream fos = new FileOutputStream(dstFile)) {
                        downloader.download(fos);
                        downloadedFiles.add(dstFile);
                        long end = System.currentTimeMillis() - start;
                        System.out.println("Downloading took " + end + "ms");
                    } catch (Exception ex) {
                        if (!ex.getMessage().contains("not_file")) {
                            ex.printStackTrace();
                            return null;
                        }
                    }
                }

                result = client.files().listFolderContinue(result.getCursor());
            } while (result.getHasMore());

            return downloadedFiles;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
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
