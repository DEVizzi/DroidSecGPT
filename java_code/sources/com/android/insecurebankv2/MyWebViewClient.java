package com.android.insecurebankv2;

import android.webkit.WebView;
import android.webkit.WebViewClient;
/* loaded from: classes.dex */
public class MyWebViewClient extends WebViewClient {
    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        view.loadUrl(url);
        return true;
    }
}
