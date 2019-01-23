package com.okta.auth;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

public class OktaRedirectActivity extends Activity {
    public static final String REDIRECT_ACTION = OktaRedirectActivity.class.getCanonicalName() + ".REDIRECT_ACTION";

    @Override
    public void onCreate(Bundle savedInstanceBundle) {
        super.onCreate(savedInstanceBundle);
        Intent intent = new Intent(this, OktaAuthenticationActivity.class);
        intent.setAction(REDIRECT_ACTION);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        intent.setData(getIntent().getData());
        startActivity(intent);
        finish();
    }
}
