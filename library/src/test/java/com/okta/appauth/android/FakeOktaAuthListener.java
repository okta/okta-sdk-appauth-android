package com.okta.appauth.android;

import net.openid.appauth.AuthorizationException;

import java.util.ArrayList;
import java.util.List;

public class FakeOktaAuthListener implements OktaAppAuth.OktaAuthListener {
    private int onSuccessCalled = 0;
    private int onTokenFailureCalled = 0;
    private List<AuthorizationException> tokenExceptions = new ArrayList<>();

    @Override
    public void onSuccess() {
        onSuccessCalled += 1;
    }

    @Override
    public void onTokenFailure(AuthorizationException ex) {
        onTokenFailureCalled += 1;
        tokenExceptions.add(ex);
    }

    public int getOnSuccessCalled() {
        return onSuccessCalled;
    }

    public int getOnTokenFailureCalled() {
        return onTokenFailureCalled;
    }

    public List<AuthorizationException> getTokenExceptions() {
        return tokenExceptions;
    }

    boolean hasCalledOnSuccess() {
        return onSuccessCalled > 0;
    }

    boolean hasCalledOnTokenFailure() {
        return onTokenFailureCalled > 0;
    }
}
