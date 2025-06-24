package com.google.android.gms.internal;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.MotionEvent;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;
/* loaded from: classes.dex */
public abstract class zzak implements zzaj {
    protected MotionEvent zzmR;
    protected DisplayMetrics zzmS;
    protected zzap zzmT;
    private zzaq zzmU;

    /* JADX INFO: Access modifiers changed from: protected */
    public zzak(Context context, zzap zzapVar, zzaq zzaqVar) {
        this.zzmT = zzapVar;
        this.zzmU = zzaqVar;
        try {
            this.zzmS = context.getResources().getDisplayMetrics();
        } catch (UnsupportedOperationException e) {
            this.zzmS = new DisplayMetrics();
            this.zzmS.density = 1.0f;
        }
    }

    private void zzS() {
        this.zzmU.reset();
    }

    private byte[] zzT() throws IOException {
        return this.zzmU.zzac();
    }

    private String zza(Context context, String str, boolean z) {
        byte[] zzT;
        try {
            synchronized (this) {
                zzS();
                if (z) {
                    zzd(context);
                } else {
                    zzc(context);
                }
                zzT = zzT();
            }
            return zzT.length == 0 ? Integer.toString(5) : zza(zzT, str);
        } catch (UnsupportedEncodingException e) {
            return Integer.toString(7);
        } catch (IOException e2) {
            return Integer.toString(3);
        } catch (NoSuchAlgorithmException e3) {
            return Integer.toString(7);
        }
    }

    @Override // com.google.android.gms.internal.zzaj
    public String zza(Context context, String str) {
        return zza(context, str, true);
    }

    String zza(byte[] bArr, String str) throws NoSuchAlgorithmException, UnsupportedEncodingException, IOException {
        byte[] array;
        if (bArr.length > 239) {
            zzS();
            zza(20, 1L);
            bArr = zzT();
        }
        if (bArr.length < 239) {
            byte[] bArr2 = new byte[239 - bArr.length];
            new SecureRandom().nextBytes(bArr2);
            array = ByteBuffer.allocate(240).put((byte) bArr.length).put(bArr).put(bArr2).array();
        } else {
            array = ByteBuffer.allocate(240).put((byte) bArr.length).put(bArr).array();
        }
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(array);
        byte[] array2 = ByteBuffer.allocate(256).put(messageDigest.digest()).put(array).array();
        byte[] bArr3 = new byte[256];
        new zzai().zzb(array2, bArr3);
        if (str != null && str.length() > 0) {
            zza(str, bArr3);
        }
        return this.zzmT.zza(bArr3, true);
    }

    @Override // com.google.android.gms.internal.zzaj
    public void zza(int i, int i2, int i3) {
        if (this.zzmR != null) {
            this.zzmR.recycle();
        }
        this.zzmR = MotionEvent.obtain(0L, i3, 1, i * this.zzmS.density, i2 * this.zzmS.density, 0.0f, 0.0f, 0, 0.0f, 0.0f, 0, 0);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void zza(int i, long j) throws IOException {
        this.zzmU.zzb(i, j);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void zza(int i, String str) throws IOException {
        this.zzmU.zzb(i, str);
    }

    @Override // com.google.android.gms.internal.zzaj
    public void zza(MotionEvent motionEvent) {
        if (motionEvent.getAction() == 1) {
            if (this.zzmR != null) {
                this.zzmR.recycle();
            }
            this.zzmR = MotionEvent.obtain(motionEvent);
        }
    }

    void zza(String str, byte[] bArr) throws UnsupportedEncodingException {
        if (str.length() > 32) {
            str = str.substring(0, 32);
        }
        new zzre(str.getBytes("UTF-8")).zzy(bArr);
    }

    @Override // com.google.android.gms.internal.zzaj
    public String zzb(Context context) {
        return zza(context, (String) null, false);
    }

    protected abstract void zzc(Context context);

    protected abstract void zzd(Context context);

    /* JADX INFO: Access modifiers changed from: protected */
    public String zzk(String str) {
        if (str == null || !str.matches("^[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}$")) {
            return str;
        }
        UUID fromString = UUID.fromString(str);
        byte[] bArr = new byte[16];
        ByteBuffer wrap = ByteBuffer.wrap(bArr);
        wrap.putLong(fromString.getMostSignificantBits());
        wrap.putLong(fromString.getLeastSignificantBits());
        return this.zzmT.zza(bArr, true);
    }
}
