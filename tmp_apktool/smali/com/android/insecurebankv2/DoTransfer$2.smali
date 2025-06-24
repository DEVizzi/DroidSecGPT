.class Lcom/android/insecurebankv2/DoTransfer$2;
.super Ljava/lang/Object;
.source "DoTransfer.java"

# interfaces
.implements Landroid/view/View$OnClickListener;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/android/insecurebankv2/DoTransfer;->onCreate(Landroid/os/Bundle;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lcom/android/insecurebankv2/DoTransfer;


# direct methods
.method constructor <init>(Lcom/android/insecurebankv2/DoTransfer;)V
    .locals 0
    .param p1, "this$0"    # Lcom/android/insecurebankv2/DoTransfer;

    .prologue
    .line 103
    iput-object p1, p0, Lcom/android/insecurebankv2/DoTransfer$2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 4
    .param p1, "v"    # Landroid/view/View;

    .prologue
    .line 107
    new-instance v0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v1, p0, Lcom/android/insecurebankv2/DoTransfer$2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    invoke-direct {v0, v1}, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;-><init>(Lcom/android/insecurebankv2/DoTransfer;)V

    const/4 v1, 0x1

    new-array v1, v1, [Ljava/lang/String;

    const/4 v2, 0x0

    const-string v3, "username"

    aput-object v3, v1, v2

    invoke-virtual {v0, v1}, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->execute([Ljava/lang/Object;)Landroid/os/AsyncTask;

    .line 108
    return-void
.end method
