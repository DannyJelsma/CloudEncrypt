package nl.dannyjelsma.cloudencrypt.download;

import java.io.File;

public interface Downloader {

    String getName();

    void downloadFiles(File downloadLoc);

}
