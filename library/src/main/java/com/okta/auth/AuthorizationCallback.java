package com.okta.auth;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;

public interface AuthorizationCallback {
    public void onSuccess(@NonNull OktaClientAPI clientAPI);

    public void onStatus(@NonNull String status);

    public void onCancel();

    public void onError(@NonNull String msg, @Nullable AuthorizationException error);
}
