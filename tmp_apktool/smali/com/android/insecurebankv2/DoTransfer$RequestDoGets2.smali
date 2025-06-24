.class public Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;
.super Landroid/os/AsyncTask;
.source "DoTransfer.java"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/android/insecurebankv2/DoTransfer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "RequestDoGets2"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Landroid/os/AsyncTask",
        "<",
        "Ljava/lang/String;",
        "Ljava/lang/String;",
        "Ljava/lang/String;",
        ">;"
    }
.end annotation


# instance fields
.field final synthetic this$0:Lcom/android/insecurebankv2/DoTransfer;


# direct methods
.method public constructor <init>(Lcom/android/insecurebankv2/DoTransfer;)V
    .locals 0
    .param p1, "this$0"    # Lcom/android/insecurebankv2/DoTransfer;

    .prologue
    .line 243
    iput-object p1, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    invoke-direct {p0}, Landroid/os/AsyncTask;-><init>()V

    return-void
.end method


# virtual methods
.method public AsyncHttpPost(Ljava/lang/String;)V
    .locals 0
    .param p1, "string"    # Ljava/lang/String;

    .prologue
    .line 250
    return-void
.end method

.method public bridge synthetic doInBackground([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .prologue
    .line 243
    check-cast p1, [Ljava/lang/String;

    invoke-virtual {p0, p1}, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->doInBackground([Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public varargs doInBackground([Ljava/lang/String;)Ljava/lang/String;
    .locals 15
    .param p1, "params"    # [Ljava/lang/String;

    .prologue
    .line 257
    const-string v8, ""

    .line 258
    .local v8, "str":Ljava/lang/String;
    const-string v8, "dinesh"

    .line 259
    new-instance v3, Lorg/apache/http/impl/client/DefaultHttpClient;

    invoke-direct {v3}, Lorg/apache/http/impl/client/DefaultHttpClient;-><init>()V

    .line 261
    .local v3, "httpclient":Lorg/apache/http/client/HttpClient;
    new-instance v4, Lorg/apache/http/client/methods/HttpPost;

    new-instance v11, Ljava/lang/StringBuilder;

    invoke-direct {v11}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, v12, Lcom/android/insecurebankv2/DoTransfer;->protocol:Ljava/lang/String;

    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v11

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, v12, Lcom/android/insecurebankv2/DoTransfer;->serverip:Ljava/lang/String;

    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v11

    const-string v12, ":"

    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v11

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, v12, Lcom/android/insecurebankv2/DoTransfer;->serverport:Ljava/lang/String;

    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v11

    const-string v12, "/getaccounts"

    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v11

    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v11

    invoke-direct {v4, v11}, Lorg/apache/http/client/methods/HttpPost;-><init>(Ljava/lang/String;)V

    .line 262
    .local v4, "httppost":Lorg/apache/http/client/methods/HttpPost;
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    const-string v12, "mySharedPreferences"

    const/4 v13, 0x0

    invoke-virtual {v11, v12, v13}, Lcom/android/insecurebankv2/DoTransfer;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v7

    .line 263
    .local v7, "settings":Landroid/content/SharedPreferences;
    const-string v11, "EncryptedUsername"

    const/4 v12, 0x0

    invoke-interface {v7, v11, v12}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v9

    .line 264
    .local v9, "username":Ljava/lang/String;
    const/4 v11, 0x0

    invoke-static {v9, v11}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object v10

    .line 267
    .local v10, "usernameBase64Byte":[B
    :try_start_0
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    new-instance v12, Ljava/lang/String;

    const-string v13, "UTF-8"

    invoke-direct {v12, v10, v13}, Ljava/lang/String;-><init>([BLjava/lang/String;)V

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->usernameBase64ByteString:Ljava/lang/String;
    :try_end_0
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_0 .. :try_end_0} :catch_0

    .line 273
    :goto_0
    const-string v11, "superSecurePassword"

    const/4 v12, 0x0

    invoke-interface {v7, v11, v12}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    .line 276
    .local v6, "password":Ljava/lang/String;
    :try_start_1
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    invoke-static {v12, v6}, Lcom/android/insecurebankv2/DoTransfer;->access$000(Lcom/android/insecurebankv2/DoTransfer;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->passNormalized:Ljava/lang/String;
    :try_end_1
    .catch Ljava/security/InvalidKeyException; {:try_start_1 .. :try_end_1} :catch_b
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_1 .. :try_end_1} :catch_d
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_1 .. :try_end_1} :catch_9
    .catch Ljavax/crypto/NoSuchPaddingException; {:try_start_1 .. :try_end_1} :catch_a
    .catch Ljava/security/InvalidAlgorithmParameterException; {:try_start_1 .. :try_end_1} :catch_8
    .catch Ljavax/crypto/IllegalBlockSizeException; {:try_start_1 .. :try_end_1} :catch_c
    .catch Ljavax/crypto/BadPaddingException; {:try_start_1 .. :try_end_1} :catch_1

    .line 282
    :goto_1
    new-instance v5, Ljava/util/ArrayList;

    const/4 v11, 0x2

    invoke-direct {v5, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 283
    .local v5, "nameValuePairs":Ljava/util/List;, "Ljava/util/List<Lorg/apache/http/NameValuePair;>;"
    new-instance v11, Lorg/apache/http/message/BasicNameValuePair;

    const-string v12, "username"

    iget-object v13, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v13, v13, Lcom/android/insecurebankv2/DoTransfer;->usernameBase64ByteString:Ljava/lang/String;

    invoke-direct {v11, v12, v13}, Lorg/apache/http/message/BasicNameValuePair;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-interface {v5, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 284
    new-instance v11, Lorg/apache/http/message/BasicNameValuePair;

    const-string v12, "password"

    iget-object v13, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v13, v13, Lcom/android/insecurebankv2/DoTransfer;->passNormalized:Ljava/lang/String;

    invoke-direct {v11, v12, v13}, Lorg/apache/http/message/BasicNameValuePair;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    invoke-interface {v5, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 286
    :try_start_2
    new-instance v11, Lorg/apache/http/client/entity/UrlEncodedFormEntity;

    invoke-direct {v11, v5}, Lorg/apache/http/client/entity/UrlEncodedFormEntity;-><init>(Ljava/util/List;)V

    invoke-virtual {v4, v11}, Lorg/apache/http/client/methods/HttpPost;->setEntity(Lorg/apache/http/HttpEntity;)V
    :try_end_2
    .catch Ljava/io/UnsupportedEncodingException; {:try_start_2 .. :try_end_2} :catch_2

    .line 293
    :goto_2
    :try_start_3
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    invoke-interface {v3, v4}, Lorg/apache/http/client/HttpClient;->execute(Lorg/apache/http/client/methods/HttpUriRequest;)Lorg/apache/http/HttpResponse;

    move-result-object v12

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->responseBody:Lorg/apache/http/HttpResponse;
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3

    .line 299
    :goto_3
    :try_start_4
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, v12, Lcom/android/insecurebankv2/DoTransfer;->responseBody:Lorg/apache/http/HttpResponse;

    invoke-interface {v12}, Lorg/apache/http/HttpResponse;->getEntity()Lorg/apache/http/HttpEntity;

    move-result-object v12

    invoke-interface {v12}, Lorg/apache/http/HttpEntity;->getContent()Ljava/io/InputStream;

    move-result-object v12

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->in:Ljava/io/InputStream;
    :try_end_4
    .catch Ljava/lang/IllegalStateException; {:try_start_4 .. :try_end_4} :catch_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_7

    .line 306
    :goto_4
    :try_start_5
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v13, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v13, v13, Lcom/android/insecurebankv2/DoTransfer;->in:Ljava/io/InputStream;

    invoke-virtual {v12, v13}, Lcom/android/insecurebankv2/DoTransfer;->convertStreamToString(Ljava/io/InputStream;)Ljava/lang/String;

    move-result-object v12

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->result:Ljava/lang/String;
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_5

    .line 311
    :goto_5
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, v12, Lcom/android/insecurebankv2/DoTransfer;->result:Ljava/lang/String;

    const-string v13, "\n"

    const-string v14, ""

    invoke-virtual {v12, v13, v14}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object v12

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->result:Ljava/lang/String;

    .line 313
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v11, v11, Lcom/android/insecurebankv2/DoTransfer;->result:Ljava/lang/String;

    if-eqz v11, :cond_0

    .line 314
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v11, v11, Lcom/android/insecurebankv2/DoTransfer;->result:Ljava/lang/String;

    const-string v12, "Correct"

    invoke-virtual {v11, v12}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    move-result v11

    const/4 v12, -0x1

    if-eq v11, v12, :cond_0

    .line 316
    :try_start_6
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    new-instance v12, Lorg/json/JSONObject;

    iget-object v13, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v13, v13, Lcom/android/insecurebankv2/DoTransfer;->result:Ljava/lang/String;

    invoke-direct {v12, v13}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->jsonObject:Lorg/json/JSONObject;

    .line 317
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, v12, Lcom/android/insecurebankv2/DoTransfer;->jsonObject:Lorg/json/JSONObject;

    const-string v13, "from"

    invoke-virtual {v12, v13}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->acc1:Ljava/lang/String;

    .line 318
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v12, v12, Lcom/android/insecurebankv2/DoTransfer;->jsonObject:Lorg/json/JSONObject;

    const-string v13, "to"

    invoke-virtual {v12, v13}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v12

    iput-object v12, v11, Lcom/android/insecurebankv2/DoTransfer;->acc2:Ljava/lang/String;
    :try_end_6
    .catch Lorg/json/JSONException; {:try_start_6 .. :try_end_6} :catch_6

    .line 326
    :cond_0
    :goto_6
    iget-object v11, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    new-instance v12, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;

    invoke-direct {v12, p0}, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;-><init>(Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;)V

    invoke-virtual {v11, v12}, Lcom/android/insecurebankv2/DoTransfer;->runOnUiThread(Ljava/lang/Runnable;)V

    .line 338
    return-object v8

    .line 268
    .end local v5    # "nameValuePairs":Ljava/util/List;, "Ljava/util/List<Lorg/apache/http/NameValuePair;>;"
    .end local v6    # "password":Ljava/lang/String;
    :catch_0
    move-exception v0

    .line 270
    .local v0, "e":Ljava/io/UnsupportedEncodingException;
    invoke-virtual {v0}, Ljava/io/UnsupportedEncodingException;->printStackTrace()V

    goto/16 :goto_0

    .line 277
    .end local v0    # "e":Ljava/io/UnsupportedEncodingException;
    .restart local v6    # "password":Ljava/lang/String;
    :catch_1
    move-exception v1

    .line 279
    .local v1, "e1":Ljava/lang/Exception;
    :goto_7
    invoke-virtual {v1}, Ljava/lang/Exception;->printStackTrace()V

    goto/16 :goto_1

    .line 287
    .end local v1    # "e1":Ljava/lang/Exception;
    .restart local v5    # "nameValuePairs":Ljava/util/List;, "Ljava/util/List<Lorg/apache/http/NameValuePair;>;"
    :catch_2
    move-exception v0

    .line 289
    .restart local v0    # "e":Ljava/io/UnsupportedEncodingException;
    invoke-virtual {v0}, Ljava/io/UnsupportedEncodingException;->printStackTrace()V

    goto/16 :goto_2

    .line 294
    .end local v0    # "e":Ljava/io/UnsupportedEncodingException;
    :catch_3
    move-exception v2

    .line 296
    .local v2, "e2":Ljava/io/IOException;
    invoke-virtual {v2}, Ljava/io/IOException;->printStackTrace()V

    goto/16 :goto_3

    .line 300
    .end local v2    # "e2":Ljava/io/IOException;
    :catch_4
    move-exception v1

    .line 302
    .restart local v1    # "e1":Ljava/lang/Exception;
    :goto_8
    invoke-virtual {v1}, Ljava/lang/Exception;->printStackTrace()V

    goto/16 :goto_4

    .line 307
    .end local v1    # "e1":Ljava/lang/Exception;
    :catch_5
    move-exception v0

    .line 309
    .local v0, "e":Ljava/io/IOException;
    invoke-virtual {v0}, Ljava/io/IOException;->printStackTrace()V

    goto :goto_5

    .line 319
    .end local v0    # "e":Ljava/io/IOException;
    :catch_6
    move-exception v0

    .line 321
    .local v0, "e":Lorg/json/JSONException;
    invoke-virtual {v0}, Lorg/json/JSONException;->printStackTrace()V

    goto :goto_6

    .line 300
    .end local v0    # "e":Lorg/json/JSONException;
    :catch_7
    move-exception v1

    goto :goto_8

    .line 277
    .end local v5    # "nameValuePairs":Ljava/util/List;, "Ljava/util/List<Lorg/apache/http/NameValuePair;>;"
    :catch_8
    move-exception v1

    goto :goto_7

    :catch_9
    move-exception v1

    goto :goto_7

    :catch_a
    move-exception v1

    goto :goto_7

    :catch_b
    move-exception v1

    goto :goto_7

    :catch_c
    move-exception v1

    goto :goto_7

    :catch_d
    move-exception v1

    goto :goto_7
.end method

.method public bridge synthetic onPostExecute(Ljava/lang/Object;)V
    .locals 0

    .prologue
    .line 243
    check-cast p1, Ljava/lang/String;

    invoke-virtual {p0, p1}, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->onPostExecute(Ljava/lang/String;)V

    return-void
.end method

.method public onPostExecute(Ljava/lang/String;)V
    .locals 0
    .param p1, "result"    # Ljava/lang/String;

    .prologue
    .line 345
    return-void
.end method

.method public bridge synthetic onProgressUpdate([Ljava/lang/Object;)V
    .locals 0

    .prologue
    .line 243
    check-cast p1, [Ljava/lang/String;

    invoke-virtual {p0, p1}, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->onProgressUpdate([Ljava/lang/String;)V

    return-void
.end method

.method public varargs onProgressUpdate([Ljava/lang/String;)V
    .locals 0
    .param p1, "progress"    # [Ljava/lang/String;

    .prologue
    .line 347
    return-void
.end method
