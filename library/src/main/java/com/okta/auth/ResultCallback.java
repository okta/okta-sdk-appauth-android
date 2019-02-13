package com.okta.auth;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.okta.openid.appauth.AuthorizationException;

public interface ResultCallback<T, U extends Exception> {
    public void onSuccess(@NonNull T result);

    public void onCancel();

    public void onError(@NonNull String msg, @Nullable U exception);
}