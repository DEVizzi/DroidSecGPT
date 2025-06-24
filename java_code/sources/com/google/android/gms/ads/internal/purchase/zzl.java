package com.google.android.gms.ads.internal.purchase;

import android.text.TextUtils;
import android.util.Base64;
import com.google.android.gms.internal.zzgd;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
@zzgd
/* loaded from: classes.dex */
public class zzl {
    public static boolean zza(PublicKey publicKey, String str, String str2) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(publicKey);
            signature.update(str.getBytes());
            if (signature.verify(Base64.decode(str2, 0))) {
                return true;
            }
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Signature verification failed.");
            return false;
        } catch (InvalidKeyException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Invalid key specification.");
            return false;
        } catch (NoSuchAlgorithmException e2) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("NoSuchAlgorithmException.");
            return false;
        } catch (SignatureException e3) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Signature exception.");
            return false;
        }
    }

    public static PublicKey zzak(String str) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(str, 0)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e2) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Invalid key specification.");
            throw new IllegalArgumentException(e2);
        }
    }

    public static boolean zzc(String str, String str2, String str3) {
        if (TextUtils.isEmpty(str2) || TextUtils.isEmpty(str) || TextUtils.isEmpty(str3)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Purchase verification failed: missing data.");
            return false;
        }
        return zza(zzak(str), str2, str3);
    }
}
