package nl.dannyjelsma.cloudencrypt.oauth;

import java.util.ArrayList;
import java.util.List;

public class OAuthTokens {

    private final List<OAuthToken> tokens;

    public OAuthTokens() {
        this.tokens = new ArrayList<>();
    }

    public void addToken(OAuthToken token) {
        tokens.add(token);
    }

    public void removeToken(OAuthToken token) {
        tokens.remove(token);
    }

    public List<OAuthToken> getTokens() {
        return tokens;
    }
}

