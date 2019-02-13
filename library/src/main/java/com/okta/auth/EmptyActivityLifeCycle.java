package com.okta.auth;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;

/*
Empty implementation
 */
class EmptyActivityLifeCycle implements Application.ActivityLifecycleCallbacks {
    @Override
    public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        //NO-OP
    }

    @Override
    public void onActivityStarted(Activity activity) {
        //NO-OP
    }

    @Override
    public void onActivityResumed(Activity activity) {
        //NO-OP
    }

    @Override
    public void onActivityPaused(Activity activity) {
        //NO-OP
    }

    @Override
    public void onActivityStopped(Activity activity) {
        //NO-OP
    }

    @Override
    public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        //NO-OP
    }

    @Override
    public void onActivityDestroyed(Activity activity) {
        //NO-OP
    }
}