.class Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$2;
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
    .line 186
    iput-object p1, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$2;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    .prologue
    .line 189
    iget-object v0, p0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask$2;->this$1:Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;

    iget-object v0, v0, Lcom/android/insecurebankv2/ChangePassword$RequestChangePasswordTask;->this$0:Lcom/android/insecurebankv2/ChangePassword;

    invoke-virtual {v0}, Lcom/android/insecurebankv2/ChangePassword;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    const-string v1, "Entered password is not complex enough."

    const/4 v2, 0x1

    invoke-static {v0, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v0

    invoke-virtual {v0}, Landroid/widget/Toast;->show()V

    .line 190
    return-void
.end method
