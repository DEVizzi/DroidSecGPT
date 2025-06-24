.class public Lcom/android/insecurebankv2/CryptoClass;
.super Ljava/lang/Object;
.source "CryptoClass.java"


# instance fields
.field base64Text:Ljava/lang/String;

.field cipherData:[B

.field cipherText:Ljava/lang/String;

.field ivBytes:[B

.field key:Ljava/lang/String;

.field plainText:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    .prologue
    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 25
    const-string v0, "This is the super secret key 123"

    iput-object v0, p0, Lcom/android/insecurebankv2/CryptoClass;->key:Ljava/lang/String;

    .line 28
    const/16 v0, 0x10

    new-array v0, v0, [B

    fill-array-data v0, :array_0

    iput-object v0, p0, Lcom/android/insecurebankv2/CryptoClass;->ivBytes:[B

    return-void

    nop

    :array_0
    .array-data 1
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
        0x0t
    .end array-data
.end method

.method public static aes256decrypt([B[B[B)[B
    .locals 4
    .param p0, "ivBytes"    # [B
    .param p1, "keyBytes"    # [B
    .param p2, "textBytes"    # [B
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;,
            Ljava/security/NoSuchAlgorithmException;,
            Ljavax/crypto/NoSuchPaddingException;,
            Ljava/security/InvalidKeyException;,
            Ljava/security/InvalidAlgorithmParameterException;,
            Ljavax/crypto/IllegalBlockSizeException;,
            Ljavax/crypto/BadPaddingException;
        }
    .end annotation

    .prologue
    .line 75
    new-instance v1, Ljavax/crypto/spec/IvParameterSpec;

    invoke-direct {v1, p0}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    .line 76
    .local v1, "ivSpec":Ljava/security/spec/AlgorithmParameterSpec;
    new-instance v2, Ljavax/crypto/spec/SecretKeySpec;

    const-string v3, "AES"

    invoke-direct {v2, p1, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 77
    .local v2, "newKey":Ljavax/crypto/spec/SecretKeySpec;
    const-string v3, "AES/CBC/PKCS5Padding"

    invoke-static {v3}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    move-result-object v0

    .line 78
    .local v0, "cipher":Ljavax/crypto/Cipher;
    const/4 v3, 0x2

    invoke-virtual {v0, v3, v2, v1}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 79
    invoke-virtual {v0, p2}, Ljavax/crypto/Cipher;->doFinal([B)[B

    move-result-object v3

    return-object v3
.end method

.method public static aes256encrypt([B[B[B)[B
    .locals 4
    .param p0, "ivBytes"    # [B
    .param p1, "keyBytes"    # [B
    .param p2, "textBytes"    # [B
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;,
            Ljava/security/NoSuchAlgorithmException;,
            Ljavax/crypto/NoSuchPaddingException;,
            Ljava/security/InvalidKeyException;,
            Ljava/security/InvalidAlgorithmParameterException;,
            Ljavax/crypto/IllegalBlockSizeException;,
            Ljavax/crypto/BadPaddingException;
        }
    .end annotation

    .prologue
    .line 52
    new-instance v1, Ljavax/crypto/spec/IvParameterSpec;

    invoke-direct {v1, p0}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    .line 53
    .local v1, "ivSpec":Ljava/security/spec/AlgorithmParameterSpec;
    new-instance v2, Ljavax/crypto/spec/SecretKeySpec;

    const-string v3, "AES"

    invoke-direct {v2, p1, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    .line 54
    .local v2, "newKey":Ljavax/crypto/spec/SecretKeySpec;
    const/4 v0, 0x0

    .line 55
    .local v0, "cipher":Ljavax/crypto/Cipher;
    const-string v3, "AES/CBC/PKCS5Padding"

    invoke-static {v3}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    move-result-object v0

    .line 56
    const/4 v3, 0x1

    invoke-virtual {v0, v3, v2, v1}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 57
    invoke-virtual {v0, p2}, Ljavax/crypto/Cipher;->doFinal([B)[B

    move-result-object v3

    return-object v3
.end method


# virtual methods
.method public aesDeccryptedString(Ljava/lang/String;)Ljava/lang/String;
    .locals 4
    .param p1, "theString"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;,
            Ljava/security/InvalidKeyException;,
            Ljava/security/NoSuchAlgorithmException;,
            Ljavax/crypto/NoSuchPaddingException;,
            Ljava/security/InvalidAlgorithmParameterException;,
            Ljavax/crypto/IllegalBlockSizeException;,
            Ljavax/crypto/BadPaddingException;
        }
    .end annotation

    .prologue
    .line 90
    iget-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->key:Ljava/lang/String;

    const-string v2, "UTF-8"

    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    move-result-object v0

    .line 91
    .local v0, "keyBytes":[B
    iget-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->ivBytes:[B

    const-string v2, "UTF-8"

    invoke-virtual {p1, v2}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    move-result-object v2

    const/4 v3, 0x0

    invoke-static {v2, v3}, Landroid/util/Base64;->decode([BI)[B

    move-result-object v2

    invoke-static {v1, v0, v2}, Lcom/android/insecurebankv2/CryptoClass;->aes256decrypt([B[B[B)[B

    move-result-object v1

    iput-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->cipherData:[B

    .line 92
    new-instance v1, Ljava/lang/String;

    iget-object v2, p0, Lcom/android/insecurebankv2/CryptoClass;->cipherData:[B

    const-string v3, "UTF-8"

    invoke-direct {v1, v2, v3}, Ljava/lang/String;-><init>([BLjava/lang/String;)V

    iput-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->plainText:Ljava/lang/String;

    .line 93
    iget-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->plainText:Ljava/lang/String;

    return-object v1
.end method

.method public aesEncryptedString(Ljava/lang/String;)Ljava/lang/String;
    .locals 4
    .param p1, "theString"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/UnsupportedEncodingException;,
            Ljava/security/InvalidKeyException;,
            Ljava/security/NoSuchAlgorithmException;,
            Ljavax/crypto/NoSuchPaddingException;,
            Ljava/security/InvalidAlgorithmParameterException;,
            Ljavax/crypto/IllegalBlockSizeException;,
            Ljavax/crypto/BadPaddingException;
        }
    .end annotation

    .prologue
    .line 103
    iget-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->key:Ljava/lang/String;

    const-string v2, "UTF-8"

    invoke-virtual {v1, v2}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    move-result-object v0

    .line 104
    .local v0, "keyBytes":[B
    iput-object p1, p0, Lcom/android/insecurebankv2/CryptoClass;->plainText:Ljava/lang/String;

    .line 105
    iget-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->ivBytes:[B

    iget-object v2, p0, Lcom/android/insecurebankv2/CryptoClass;->plainText:Ljava/lang/String;

    const-string v3, "UTF-8"

    invoke-virtual {v2, v3}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    move-result-object v2

    invoke-static {v1, v0, v2}, Lcom/android/insecurebankv2/CryptoClass;->aes256encrypt([B[B[B)[B

    move-result-object v1

    iput-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->cipherData:[B

    .line 106
    iget-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->cipherData:[B

    const/4 v2, 0x0

    invoke-static {v1, v2}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    move-result-object v1

    iput-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->cipherText:Ljava/lang/String;

    .line 107
    iget-object v1, p0, Lcom/android/insecurebankv2/CryptoClass;->cipherText:Ljava/lang/String;

    return-object v1
.end method
