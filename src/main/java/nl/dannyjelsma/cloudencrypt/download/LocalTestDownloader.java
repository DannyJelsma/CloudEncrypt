package nl.dannyjelsma.cloudencrypt.download;

import java.io.File;

public class LocalTestDownloader implements Downloader {

    @Override
    public String getName() {
        return "local test (development)";
    }

    @Override
    public void downloadFiles(File downloadLoc) {

    }
}
