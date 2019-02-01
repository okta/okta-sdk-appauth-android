package com.okta.auth;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.WorkerThread;
import android.support.customtabs.CustomTabsIntent;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationManagementRequest;
import net.openid.appauth.browser.AnyBrowserMatcher;
import net.openid.appauth.browser.BrowserDescriptor;
import net.openid.appauth.browser.BrowserMatcher;
import net.openid.appauth.browser.BrowserSelector;
import net.openid.appauth.browser.BrowserWhitelist;
import net.openid.appauth.browser.CustomTabManager;
import net.openid.appauth.browser.VersionedBrowserMatcher;
import net.openid.appauth.internal.Logger;

import org.json.JSONException;

public class OktaAuthenticationActivity extends Activity {
    //static final String EXTRA_AUTH_INTENT = "com.okta.auth.AUTH_INTENT";
    static final String EXTRA_AUTH_STARTED = "com.okta.auth.AUTH_STARTED";
    static final String EXTRA_AUTH_URI = "com.okta.auth.AUTH_URI";
    static final String EXTRA_TAB_OPTIONS = "com.okta.auth.TAB_OPTIONS";

    private CustomTabManager mTabManager;

    private boolean mAuthStarted = false;
    private Uri mAuthUri;
    private int mCustomTabColor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //In case redirect activity created a new instance of auth activity.
        if (OktaRedirectActivity.REDIRECT_ACTION.equals(getIntent().getAction())) {
            setResult(RESULT_CANCELED);
            finish();
            return;
        }

        Bundle bundle;
        if (savedInstanceState == null) {
            bundle = getIntent().getExtras();
        } else {
            bundle = savedInstanceState;
        }

        if (bundle != null) {
            mAuthUri = bundle.getParcelable(EXTRA_AUTH_URI);
            mCustomTabColor = bundle.getInt(EXTRA_TAB_OPTIONS, -1);
            mAuthStarted = bundle.getBoolean(EXTRA_AUTH_STARTED, false);
            Intent browserIntent = createBrowserIntent();
            if (browserIntent != null) {
                startActivity(browserIntent);
                mAuthStarted = true;
            } else {
                setResult(RESULT_CANCELED);
                finish();
            }
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean(EXTRA_AUTH_STARTED, mAuthStarted);
        outState.putParcelable(EXTRA_AUTH_URI, mAuthUri);
        outState.putInt(EXTRA_TAB_OPTIONS, mCustomTabColor);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!mAuthStarted) {
            // The custom tab was closed without getting a result.
            sendResult(RESULT_CANCELED, null);
        }
        mAuthStarted = false;
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (OktaRedirectActivity.REDIRECT_ACTION.equals(intent.getAction())) {
            // We have successfully redirected back to this activity. Return the result and close.
            sendResult(RESULT_OK, intent);
        }
    }

    private Intent createBrowserIntent() {
        BrowserDescriptor descriptor = BrowserSelector.select(this,
                new BrowserWhitelist(VersionedBrowserMatcher.CHROME_CUSTOM_TAB,
                        VersionedBrowserMatcher.CHROME_BROWSER,
                        VersionedBrowserMatcher.FIREFOX_CUSTOM_TAB,
                        VersionedBrowserMatcher.FIREFOX_BROWSER,
                        VersionedBrowserMatcher.SAMSUNG_CUSTOM_TAB,
                        VersionedBrowserMatcher.SAMSUNG_BROWSER));
        if (descriptor == null) {
            return null;
        }
        mTabManager = new CustomTabManager(this);
        mTabManager.bind(descriptor.packageName);
        CustomTabsIntent.Builder intentBuilder = mTabManager.createTabBuilder(mAuthUri);
        if (mCustomTabColor > 0) {
            intentBuilder.setToolbarColor(mCustomTabColor);
        }
        CustomTabsIntent tabsIntent = intentBuilder.build();
        tabsIntent.intent.addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
        tabsIntent.intent.setPackage(descriptor.packageName);
        tabsIntent.intent.setData(mAuthUri);
        return tabsIntent.intent;
    }

    private void sendResult(int rc, Intent intent) {
        setResult(rc, intent);
        finish();
    }

    @Override
    protected void onDestroy() {
        if (mTabManager != null) {
            mTabManager.dispose();
        }
        super.onDestroy();
    }
}
