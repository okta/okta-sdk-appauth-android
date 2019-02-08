package com.okta.auth;

import android.os.Handler;
import android.os.Looper;

import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Executor Service that that runs tasks on ui thread.
 * Can't be shut down for obvious reasons.
 */
public class MainThreadExecutor extends AbstractExecutorService {

    private final Handler mHandler;

    public MainThreadExecutor() {
        mHandler = new Handler(Looper.getMainLooper());
    }

    @Override
    public void shutdown() {
        mHandler.removeCallbacks(null, null);
    }

    @Override
    public List<Runnable> shutdownNow() {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean isShutdown() {
        return false;
    }

    @Override
    public boolean isTerminated() {
        return false;
    }

    @Override
    public boolean awaitTermination(long timeout, TimeUnit unit) {
        return false;
    }

    @Override
    public void execute(Runnable command) {
        if (mHandler.getLooper() == Looper.myLooper()) {
            command.run();
        } else {
            mHandler.post(command);
        }
    }
}
