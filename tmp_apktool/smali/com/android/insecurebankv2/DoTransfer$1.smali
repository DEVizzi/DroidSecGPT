.class Lcom/android/insecurebankv2/DoTransfer$1;
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
    .line 92
    iput-object p1, p0, Lcom/android/insecurebankv2/DoTransfer$1;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onClick(Landroid/view/View;)V
    .locals 4
    .param p1, "v"    # Landroid/view/View;

    .prologue
    .line 96
    iget-object v1, p0, Lcom/android/insecurebankv2/DoTransfer$1;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$1;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    const v2, 0x7f0d006b

    invoke-virtual {v0, v2}, Lcom/android/insecurebankv2/DoTransfer;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/EditText;

    iput-object v0, v1, Lcom/android/insecurebankv2/DoTransfer;->from:Landroid/widget/EditText;

    .line 97
    iget-object v1, p0, Lcom/android/insecurebankv2/DoTransfer$1;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$1;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    const v2, 0x7f0d006d

    invoke-virtual {v0, v2}, Lcom/android/insecurebankv2/DoTransfer;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/EditText;

    iput-object v0, v1, Lcom/android/insecurebankv2/DoTransfer;->to:Landroid/widget/EditText;

    .line 98
    new-instance v0, Lcom/android/insecurebankv2/DoTransfer$RequestDoTransferTask;

    iget-object v1, p0, Lcom/android/insecurebankv2/DoTransfer$1;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    invoke-direct {v0, v1}, Lcom/android/insecurebankv2/DoTransfer$RequestDoTransferTask;-><init>(Lcom/android/insecurebankv2/DoTransfer;)V

    const/4 v1, 0x1

    new-array v1, v1, [Ljava/lang/String;

    const/4 v2, 0x0

    const-string v3, "username"

    aput-object v3, v1, v2

    invoke-virtual {v0, v1}, Lcom/android/insecurebankv2/DoTransfer$RequestDoTransferTask;->execute([Ljava/lang/Object;)Landroid/os/AsyncTask;

    .line 99
    return-void
.end method
