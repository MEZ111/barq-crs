package sa.barq.fixture;

// Deliberately insecure synthetic benchmark fixture. Never ship this code.
final class UnsafeWebView {
    void configure(android.webkit.WebView view, Object bridge) {
        view.getSettings().setJavaScriptEnabled(true);
        view.addJavascriptInterface(bridge, "FixtureBridge");
        view.getSettings().setAllowUniversalAccessFromFileURLs(true);
        android.webkit.WebView.setWebContentsDebuggingEnabled(true);
    }

    void onReceivedSslError(
        android.webkit.WebView view,
        android.webkit.SslErrorHandler handler,
        android.net.http.SslError error
    ) {
        handler.proceed();
    }
}
