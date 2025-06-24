.class public Lcom/android/insecurebankv2/DoTransfer;
.super Landroid/app/Activity;
.source "DoTransfer.java"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;,
        Lcom/android/insecurebankv2/DoTransfer$RequestDoTransferTask;
    }
.end annotation


# static fields
.field public static final MYPREFS2:Ljava/lang/String; = "mySharedPreferences"


# instance fields
.field acc1:Ljava/lang/String;

.field acc2:Ljava/lang/String;

.field amount:Landroid/widget/EditText;

.field button1:Landroid/widget/Button;

.field from:Landroid/widget/EditText;

.field getAccounts:Landroid/widget/Button;

.field in:Ljava/io/InputStream;

.field jsonObject:Lorg/json/JSONObject;

.field number:Ljava/lang/String;

.field passNormalized:Ljava/lang/String;

.field phoneNumber:Landroid/widget/EditText;

.field protocol:Ljava/lang/String;

.field reader:Ljava/io/BufferedReader;

.field responseBody:Lorg/apache/http/HttpResponse;

.field result:Ljava/lang/String;

.field serverDetails:Landroid/content/SharedPreferences;

.field serverip:Ljava/lang/String;

.field serverport:Ljava/lang/String;

.field to:Landroid/widget/EditText;

.field transfer:Landroid/widget/Button;

.field usernameBase64ByteString:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 1

    .prologue
    .line 50
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V

    .line 65
    const-string v0, "5554"

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->number:Ljava/lang/String;

    .line 74
    const-string v0, ""

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->serverip:Ljava/lang/String;

    .line 75
    const-string v0, ""

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->serverport:Ljava/lang/String;

    .line 76
    const-string v0, "http://"

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->protocol:Ljava/lang/String;

    .line 243
    return-void
.end method

.method static synthetic access$000(Lcom/android/insecurebankv2/DoTransfer;Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p0, "x0"    # Lcom/android/insecurebankv2/DoTransfer;
    .param p1, "x1"    # Ljava/lang/String;
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
    .line 50
    invoke-direct {p0, p1}, Lcom/android/insecurebankv2/DoTransfer;->getNormalizedPassword(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method private getNormalizedPassword(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    .param p1, "password"    # Ljava/lang/String;
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
    .line 356
    new-instance v0, Lcom/android/insecurebankv2/CryptoClass;

    invoke-direct {v0}, Lcom/android/insecurebankv2/CryptoClass;-><init>()V

    .line 357
    .local v0, "crypt":Lcom/android/insecurebankv2/CryptoClass;
    invoke-virtual {v0, p1}, Lcom/android/insecurebankv2/CryptoClass;->aesDeccryptedString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    return-object v1
.end method


# virtual methods
.method public callPreferences()V
    .locals 2

    .prologue
    .line 406
    new-instance v0, Landroid/content/Intent;

    const-class v1, Lcom/android/insecurebankv2/FilePrefActivity;

    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 407
    .local v0, "i":Landroid/content/Intent;
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/DoTransfer;->startActivity(Landroid/content/Intent;)V

    .line 408
    return-void
.end method

.method public convertStreamToString(Ljava/io/InputStream;)Ljava/lang/String;
    .locals 6
    .param p1, "in"    # Ljava/io/InputStream;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/io/IOException;
        }
    .end annotation

    .prologue
    .line 364
    :try_start_0
    new-instance v3, Ljava/io/BufferedReader;

    new-instance v4, Ljava/io/InputStreamReader;

    const-string v5, "UTF-8"

    invoke-direct {v4, p1, v5}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/lang/String;)V

    invoke-direct {v3, v4}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V

    iput-object v3, p0, Lcom/android/insecurebankv2/DoTransfer;->reader:Ljava/io/BufferedReader;
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_0

    .line 369
    :goto_0
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 370
    .local v2, "sb":Ljava/lang/StringBuilder;
    const/4 v1, 0x0

    .line 371
    .local v1, "line":Ljava/lang/String;
    :goto_1
    iget-object v3, p0, Lcom/android/insecurebankv2/DoTransfer;->reader:Ljava/io/BufferedReader;

    invoke-virtual {v3}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_0

    .line 372
    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    const-string v4, "\n"

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_1

    .line 365
    .end local v1    # "line":Ljava/lang/String;
    .end local v2    # "sb":Ljava/lang/StringBuilder;
    :catch_0
    move-exception v0

    .line 367
    .local v0, "e":Ljava/io/UnsupportedEncodingException;
    invoke-virtual {v0}, Ljava/io/UnsupportedEncodingException;->printStackTrace()V

    goto :goto_0

    .line 373
    .end local v0    # "e":Ljava/io/UnsupportedEncodingException;
    .restart local v1    # "line":Ljava/lang/String;
    .restart local v2    # "sb":Ljava/lang/StringBuilder;
    :cond_0
    invoke-virtual {p1}, Ljava/io/InputStream;->close()V

    .line 374
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    return-object v3
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 3
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    const/4 v2, 0x0

    .line 82
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    .line 83
    const v0, 0x7f04001b

    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/DoTransfer;->setContentView(I)V

    .line 86
    invoke-static {p0}, Landroid/preference/PreferenceManager;->getDefaultSharedPreferences(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v0

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->serverDetails:Landroid/content/SharedPreferences;

    .line 87
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->serverDetails:Landroid/content/SharedPreferences;

    const-string v1, "serverip"

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->serverip:Ljava/lang/String;

    .line 88
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->serverDetails:Landroid/content/SharedPreferences;

    const-string v1, "serverport"

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->serverport:Ljava/lang/String;

    .line 91
    const v0, 0x7f0d0071

    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/DoTransfer;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/Button;

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->transfer:Landroid/widget/Button;

    .line 92
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->transfer:Landroid/widget/Button;

    new-instance v1, Lcom/android/insecurebankv2/DoTransfer$1;

    invoke-direct {v1, p0}, Lcom/android/insecurebankv2/DoTransfer$1;-><init>(Lcom/android/insecurebankv2/DoTransfer;)V

    invoke-virtual {v0, v1}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 102
    const v0, 0x7f0d006e

    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/DoTransfer;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/Button;

    iput-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->button1:Landroid/widget/Button;

    .line 103
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer;->button1:Landroid/widget/Button;

    new-instance v1, Lcom/android/insecurebankv2/DoTransfer$2;

    invoke-direct {v1, p0}, Lcom/android/insecurebankv2/DoTransfer$2;-><init>(Lcom/android/insecurebankv2/DoTransfer;)V

    invoke-virtual {v0, v1}, Landroid/widget/Button;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 110
    return-void
.end method

.method public onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2
    .param p1, "menu"    # Landroid/view/Menu;

    .prologue
    .line 381
    invoke-virtual {p0}, Lcom/android/insecurebankv2/DoTransfer;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    const v1, 0x7f0e0002

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    .line 382
    const/4 v0, 0x1

    return v0
.end method

.method public onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 5
    .param p1, "item"    # Landroid/view/MenuItem;

    .prologue
    const/4 v2, 0x1

    .line 391
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    .line 392
    .local v1, "id":I
    const v3, 0x7f0d009d

    if-ne v1, v3, :cond_0

    .line 393
    invoke-virtual {p0}, Lcom/android/insecurebankv2/DoTransfer;->callPreferences()V

    .line 401
    :goto_0
    return v2

    .line 395
    :cond_0
    const v3, 0x7f0d009e

    if-ne v1, v3, :cond_1

    .line 396
    new-instance v0, Landroid/content/Intent;

    invoke-virtual {p0}, Lcom/android/insecurebankv2/DoTransfer;->getBaseContext()Landroid/content/Context;

    move-result-object v3

    const-class v4, Lcom/android/insecurebankv2/LoginActivity;

    invoke-direct {v0, v3, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 397
    .local v0, "i":Landroid/content/Intent;
    const/high16 v3, 0x4000000

    invoke-virtual {v0, v3}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    .line 398
    invoke-virtual {p0, v0}, Lcom/android/insecurebankv2/DoTransfer;->startActivity(Landroid/content/Intent;)V

    goto :goto_0

    .line 401
    .end local v0    # "i":Landroid/content/Intent;
    :cond_1
    invoke-super {p0, p1}, Landroid/app/Activity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    move-result v2

    goto :goto_0
.end method
