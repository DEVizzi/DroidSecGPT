package com.google.android.gms.internal;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
/* loaded from: classes.dex */
public abstract class zzbl {
    private static MessageDigest zzrK = null;
    protected Object zzqt = new Object();

    /* JADX INFO: Access modifiers changed from: protected */
    public MessageDigest zzcu() {
        MessageDigest messageDigest;
        synchronized (this.zzqt) {
            if (zzrK != null) {
                messageDigest = zzrK;
            } else {
                for (int i = 0; i < 2; i++) {
                    try {
                        zzrK = MessageDigest.getInstance("MD5");
                    } catch (NoSuchAlgorithmException e) {
                    }
                }
                messageDigest = zzrK;
            }
        }
        return messageDigest;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract byte[] zzy(String str);
}
