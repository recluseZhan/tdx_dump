#include<linux/init.h>
#include<linux/module.h>
#include<linux/string.h>
#include<linux/kernel.h>
#include<linux/export.h>
#include<linux/scatterlist.h>
#include<linux/crypto.h>
#include <linux/err.h>
#include<crypto/skcipher.h>

MODULE_LICENSE("GPL");

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
static const unsigned char aes_key[AES_KEY_SIZE] = "0123456789abcdef";

#define DUMP_SIZE 32
static unsigned char data_share[DUMP_SIZE];

static int aes_encrypt(const unsigned char *input, unsigned char *output){
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg_src, sg_dst;
    int ret;
    // allocate context
    tfm = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);
    if(IS_ERR(tfm)){
        printk(KERN_ERR"Error allocating cipher\n");
        return PTR_ERR(tfm);
    }
    // init req
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if(!req){
        printk(KERN_ERR"Error allocating request\n");
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }
    // set key
    ret = crypto_skcipher_setkey(tfm, aes_key, AES_KEY_SIZE);
    if(ret){
        printk(KERN_ERR"Error setting key\n");
        skcipher_request_free(req);
        crypto_free_skcipher(tfm);
        return ret;
    }
    // prepare input and output scatterlist
    sg_init_one(&sg_src, input, AES_BLOCK_SIZE);
    sg_init_one(&sg_dst, output, AES_BLOCK_SIZE);
    // init req
    skcipher_request_set_crypt(req, &sg_src, &sg_dst, AES_BLOCK_SIZE, NULL);    
    // encrypt
    ret = crypto_skcipher_encrypt(req);
    if(ret){
        printk(KERN_ERR"Encryption failed\n");
        skcipher_request_free(req);
        crypto_free_skcipher(tfm);
        return ret;
    }
    // free
    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
    return ret;
}
static int aes_decrypt(const unsigned char *input, unsigned char *output){
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg_src, sg_dst;
    int ret;
    // allocate context
    tfm = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);
    if(IS_ERR(tfm)){
        printk(KERN_ERR"Error allocating cipher\n");
        return PTR_ERR(tfm);
    }
    // init req
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if(!req){
        printk(KERN_ERR"Error allocating request\n");
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }
    // set key
    ret = crypto_skcipher_setkey(tfm, aes_key, AES_KEY_SIZE);
    if(ret){
        printk(KERN_ERR"Error setting key\n");
        skcipher_request_free(req);
        crypto_free_skcipher(tfm);
        return ret;
    }
    // prepare input and output scatterlist
    sg_init_one(&sg_src, input, AES_BLOCK_SIZE);
    sg_init_one(&sg_dst, output, AES_BLOCK_SIZE);
    // init req
    skcipher_request_set_crypt(req, &sg_src, &sg_dst, AES_BLOCK_SIZE, NULL);    
    // decrypt
    ret = crypto_skcipher_decrypt(req);
    if(ret){
        printk(KERN_ERR"Decryption failed\n");
        skcipher_request_free(req);
        crypto_free_skcipher(tfm);
        return ret;
    }
    // free
    skcipher_request_free(req);
    crypto_free_skcipher(tfm);
    return ret;
}

static void work_encrypt(const unsigned char *input, unsigned char *output){
    for(int i = 0; i < DUMP_SIZE / AES_BLOCK_SIZE; i++){
        aes_encrypt(input + i * AES_BLOCK_SIZE, output + i * AES_BLOCK_SIZE);
    }
}
static void work_decrypt(const unsigned char *input, unsigned char *output){
    for(int i = 0; i < DUMP_SIZE / AES_BLOCK_SIZE; i++){
        aes_decrypt(input + i * AES_BLOCK_SIZE, output + i * AES_BLOCK_SIZE);
    }
}

static void work_dump(unsigned char *data_crypto){
    memcpy(data_share,data_crypto,DUMP_SIZE);
}

static int __init work_init(void)
{
    unsigned char data[DUMP_SIZE]="hello,world!thiswork";
    unsigned char data_crypto[DUMP_SIZE];
    unsigned char data_d[DUMP_SIZE];
    
    work_encrypt(data, data_crypto);
    printk("en:");
    for(int i = 0; i < DUMP_SIZE; i++)
        printk(KERN_CONT"%02x ",data_crypto[i]);
    
    
    work_decrypt(data_crypto, data_d);
    printk("de:  ");
    for(int i=0; i < DUMP_SIZE; i++)
        printk(KERN_CONT"%c ",data_d[i]);
        
    
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
