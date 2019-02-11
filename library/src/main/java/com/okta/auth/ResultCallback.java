package com.okta.auth;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.okta.openid.appauth.AuthorizationException;

public interface ResultCallback {
    public void onSuccess(@NonNull OktaClientAPI clientAPI);

    public void onCancel();

    public void onError(@NonNull String msg, @Nullable AuthorizationException error);
}
