package com.okta.auth;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;

public interface AuthorizationCallback {
    public void onSuccess(OktaClientAPI clientAPI);

    public void onStatus(String status);

    public void onCancel();

    public void onError(String msg, AuthorizationException error);
}
