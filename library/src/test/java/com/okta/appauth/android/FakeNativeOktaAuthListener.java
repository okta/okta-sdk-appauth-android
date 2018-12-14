package com.okta.appauth.android;

import android.support.annotation.NonNull;

import net.openid.appauth.AuthorizationException;

import java.util.ArrayList;
import java.util.List;

public class FakeNativeOktaAuthListener implements OktaAppAuth.OktaNativeAuthListener {
    private int onSuccessCalled = 0;
    private int onTokenFailureCalled = 0;
    private List<AuthenticationError> tokenExceptions = new ArrayList<>();

    @Override
    public void onSuccess() {
        onSuccessCalled += 1;
    }

    @Override
    public void onTokenFailure(@NonNull AuthenticationError ex) {
        onTokenFailureCalled += 1;
        tokenExceptions.add(ex);
    }

    public int getOnSuccessCalled() {
        return onSuccessCalled;
    }

    public int getOnTokenFailureCalled() {
        return onTokenFailureCalled;
    }

    public List<AuthenticationError> getTokenExceptions() {
        return tokenExceptions;
    }

    boolean hasCalledOnSuccess() {
        return onSuccessCalled > 0;
    }

    boolean hasCalledOnTokenFailure() {
        return onTokenFailureCalled > 0;
    }
}
