.class Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;
.super Ljava/lang/Object;
.source "DoTransfer.java"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->doInBackground([Ljava/lang/String;)Ljava/lang/String;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x0
    name = null
.end annotation


# instance fields
.field final synthetic this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;


# direct methods
.method constructor <init>(Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;)V
    .locals 0
    .param p1, "this$1"    # Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    .prologue
    .line 326
    iput-object p1, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 3

    .prologue
    .line 331
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    const-string v1, "result"

    invoke-virtual {v0, v1}, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->AsyncHttpPost(Ljava/lang/String;)V

    .line 332
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v1, v0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v0, v0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    const v2, 0x7f0d006b

    invoke-virtual {v0, v2}, Lcom/android/insecurebankv2/DoTransfer;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/EditText;

    iput-object v0, v1, Lcom/android/insecurebankv2/DoTransfer;->from:Landroid/widget/EditText;

    .line 333
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v1, v0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v0, v0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    const v2, 0x7f0d006d

    invoke-virtual {v0, v2}, Lcom/android/insecurebankv2/DoTransfer;->findViewById(I)Landroid/view/View;

    move-result-object v0

    check-cast v0, Landroid/widget/EditText;

    iput-object v0, v1, Lcom/android/insecurebankv2/DoTransfer;->to:Landroid/widget/EditText;

    .line 334
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v0, v0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v0, v0, Lcom/android/insecurebankv2/DoTransfer;->from:Landroid/widget/EditText;

    iget-object v1, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v1, v1, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v1, v1, Lcom/android/insecurebankv2/DoTransfer;->acc1:Ljava/lang/String;

    invoke-virtual {v0, v1}, Landroid/widget/EditText;->setText(Ljava/lang/CharSequence;)V

    .line 335
    iget-object v0, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v0, v0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v0, v0, Lcom/android/insecurebankv2/DoTransfer;->to:Landroid/widget/EditText;

    iget-object v1, p0, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2$1;->this$1:Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;

    iget-object v1, v1, Lcom/android/insecurebankv2/DoTransfer$RequestDoGets2;->this$0:Lcom/android/insecurebankv2/DoTransfer;

    iget-object v1, v1, Lcom/android/insecurebankv2/DoTransfer;->acc2:Ljava/lang/String;

    invoke-virtual {v0, v1}, Landroid/widget/EditText;->setText(Ljava/lang/CharSequence;)V

    .line 336
    return-void
.end method
