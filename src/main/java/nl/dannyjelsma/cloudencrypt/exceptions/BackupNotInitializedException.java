package nl.dannyjelsma.cloudencrypt.exceptions;

public class BackupNotInitializedException extends RuntimeException {

    public BackupNotInitializedException() {
        super("The backup folder requires first time initialization!");
    }

}
