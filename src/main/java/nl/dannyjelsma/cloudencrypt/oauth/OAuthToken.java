package nl.dannyjelsma.cloudencrypt.oauth;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OAuthToken {

    private String site;
    private String refreshToken;

    public OAuthToken() {}

    public OAuthToken(String site, String refreshToken) {
        this.site = site;
        this.refreshToken = refreshToken;
    }

    public String getSite() {
        return site;
    }

    public void setSite(String site) {
        this.site = site;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
