#include<linux/init.h>
#include<linux/module.h>
#include<linux/mm.h>
#include<linux/mm_types.h>
#include<linux/sched.h>
#include<linux/export.h>
#include<linux/init_task.h>
#include<linux/string.h>
#include<linux/kernel.h>

#include<linux/scatterlist.h>
#include<linux/crypto.h>
#include <linux/err.h>
#include<linux/random.h>
#include<crypto/skcipher.h>

MODULE_LICENSE("GPL");

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
static const unsigned char aes_key[AES_KEY_SIZE] = "0123456789abcdef";

static int size = 4096;
static __attribute__((aligned(4096))) unsigned char data[4096];
static __attribute__((aligned(4096))) unsigned char data_crypto[4096];
static __attribute__((aligned(4096))) unsigned char data_share[4096];


static int aes_encrypt(const unsigned char *input, unsigned char *output){
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg_src, sg_dst;
    int ret;
    tfm = crypto_alloc_skcipher("ecb-aes-aesni",0,0);
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    ret = crypto_skcipher_setkey(tfm, aes_key, AES_KEY_SIZE);
    sg_init_one(&sg_src, input, AES_BLOCK_SIZE);
    sg_init_one(&sg_dst, output, AES_BLOCK_SIZE);
    skcipher_request_set_crypt(req,&sg_src,&sg_dst,AES_BLOCK_SIZE,NULL);
    ret = crypto_skcipher_encrypt(req);
    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
    return 0;
}

void page_init(void){    
    memset(data,0,size);
    memset(data_crypto,0,size);
    memset(data_share,0,size);
}

void work_dump(void){
    memcpy(data_share,data_crypto,size);
}

static int __init work_init(void)
{
    page_init();
    aes_encrypt(data, data_crypto);
    work_dump();
    
    printk(KERN_ALERT"work module is entering..\n");


    return 0;
}

static void __exit work_exit(void)
{
    printk(KERN_ALERT"work module is leaving..\n");
    
}
//EXPORT_SYMBOL();

module_init(work_init);
module_exit(work_exit);
