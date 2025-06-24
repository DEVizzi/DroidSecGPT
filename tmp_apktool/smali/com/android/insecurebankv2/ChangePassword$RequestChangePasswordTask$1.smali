.class Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;
.super Ljava/lang/Object;
.source "ChangePassword.java"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->postData(Ljava/lang/String;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;


# direct methods
.method constructor <init>(Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;)V
    .locals 0
    .param p1, "this$1"    # Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    .prologue
    .line 152
    iput-object p1, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 8

    .prologue
    .line 155
    iget-object v5, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword;->result:Ljava/lang/String;

    if-eqz v5, :cond_0

    .line 156
    iget-object v5, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword;->result:Ljava/lang/String;

    const-string v6, "Change Password Successful"

    invoke-virtual {v5, v6}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    move-result v5

    const/4 v6, -0x1

    if-eq v5, v6, :cond_0

    .line 160
    :try_start_0
    new-instance v1, Lorg/json/JSONObject;

    iget-object v5, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword;->result:Ljava/lang/String;

    invoke-direct {v1, v5}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 161
    .local v1, "jsonObject":Lorg/json/JSONObject;
    const-string v5, "message"

    invoke-virtual {v1, v5}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 162
    .local v2, "login_response_message":Ljava/lang/String;
    iget-object v5, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    invoke-virtual {v5}, Lcom/android/insecurebankv2/ChangePassword;->getApplicationContext()Landroid/content/Context;

    move-result-object v5

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    const-string v7, ". Restart application to Continue."

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    const/4 v7, 0x1

    invoke-static {v5, v6, v7}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v5

    invoke-virtual {v5}, Landroid/widget/Toast;->show()V

    .line 163
    iget-object v5, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    invoke-virtual {v5}, Lcom/android/insecurebankv2/ChangePassword;->getApplicationContext()Landroid/content/Context;

    move-result-object v5

    const-string v6, "phone"

    invoke-virtual {v5, v6}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/telephony/TelephonyManager;

    .line 164
    .local v3, "phoneManager":Landroid/telephony/TelephonyManager;
    invoke-virtual {v3}, Landroid/telephony/TelephonyManager;->getLine1Number()Ljava/lang/String;

    move-result-object v4

    .line 165
    .local v4, "phoneNumber":Ljava/lang/String;
    sget-object v5, Ljava/lang/System;->out:Ljava/io/PrintStream;

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v7, "phonno:"

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v5, v6}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 172
    iget-object v5, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v5, v5, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    iget-object v6, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$1;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v6, v6, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    iget-object v6, v6, Lcom/android/insecurebankv2/ChangePassword;->changePassword_text:Landroid/widget/EditText;

    invoke-virtual {v6}, Landroid/widget/EditText;->getText()Landroid/text/Editable;

    move-result-object v6

    invoke-virtual {v6}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-static {v5, v4, v6}, Lcom/android/insecurebankv2/ChangePassword;->access$200(Lcom/android/insecurebankv2/ChangePassword;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 181
    .end local v1    # "jsonObject":Lorg/json/JSONObject;
    .end local v2    # "login_response_message":Ljava/lang/String;
    .end local v3    # "phoneManager":Landroid/telephony/TelephonyManager;
    .end local v4    # "phoneNumber":Ljava/lang/String;
    :cond_0
    :goto_0
    return-void

    .line 175
    :catch_0
    move-exception v0

    .line 177
    .local v0, "e":Lorg/json/JSONException;
    invoke-virtual {v0}, Lorg/json/JSONException;->printStackTrace()V

    goto :goto_0
.end method
