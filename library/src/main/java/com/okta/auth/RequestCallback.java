package com.okta.auth;

import android.support.annotation.NonNull;

public interface RequestCallback<T, U extends Exception> {
    public void onSuccess(@NonNull T result);

    public void onError(String error, U exception);
}
