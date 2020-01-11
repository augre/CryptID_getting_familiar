#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmp.h"

#include "CryptID.h"
#include "util/Validation.h"


void writePublicParToFile(PublicParameters* publicParameters)
{
    FILE * fp;
    fp = fopen ("publicParameters","wb");
    if (fp != NULL) {
        fwrite(publicParameters, sizeof(struct PublicParameters), 1, fp);
        fclose(fp);
    }
}

void writeCipherTextToFile(CipherTextTuple* ciphertext)
{
    FILE * fp;
    fp = fopen ("cipher","wb");
    if (fp != NULL) {

        fwrite(&ciphertext->cipherU, sizeof(ciphertext->cipherU), 1, fp);

        fwrite(&ciphertext->cipherVLength, sizeof(ciphertext->cipherVLength), 1, fp);
        fwrite(ciphertext->cipherV, ciphertext->cipherVLength + 1, 1, fp);

        fwrite(&ciphertext->cipherWLength, sizeof(ciphertext->cipherWLength),1, fp);
        fwrite(ciphertext->cipherW, ciphertext->cipherWLength + 1, 1, fp);

        fclose(fp);
    }
    printf("beleirt:\n");
    printf("VLength: %lu\n", ciphertext->cipherVLength);
    printf("%s\n", ciphertext->cipherV);
    printf("%lu\n", ciphertext->cipherWLength);
    printf("%s\n", ciphertext->cipherW);
}


void writePrivateKeyToFile(AffinePoint privateKey)
{
    FILE * fp;
    fp = fopen ("pk","wb");
    if (fp != NULL) {
        fwrite(&privateKey, sizeof(struct AffinePoint), 1, fp);
        fclose(fp);
    }
}

void readPublicParFromFile(PublicParameters* publicParameters)
{
    FILE * fp;
    fp = fopen("publicParameters", "rb");
    if (fp != NULL) {

        fread(publicParameters, sizeof(struct PublicParameters), 1, fp);

        fclose(fp);
    }

}

void readCipherTextFromFile(CipherTextTuple* ciphertext)
{
    FILE * fp;
    fp = fopen("cipher", "rb");
    if (fp != NULL) {

        fread(&ciphertext->cipherU, sizeof(ciphertext->cipherU), 1, fp);
        fread(&ciphertext->cipherVLength, sizeof(ciphertext->cipherVLength), 1, fp);

	ciphertext->cipherV = malloc(ciphertext->cipherVLength + 1);
        fread(ciphertext->cipherV, ciphertext->cipherVLength + 1, 1, fp);
        fread(&ciphertext->cipherWLength, sizeof(ciphertext->cipherWLength), 1, fp);

	ciphertext->cipherW = malloc(ciphertext->cipherWLength + 1);
        fread(ciphertext->cipherW, ciphertext->cipherWLength + 1, 1, fp);

        fclose(fp);
    }

    else printf("Can't open file");
    printf("kiolvasott:\n");
    printf("VLength: %lu\n", ciphertext->cipherVLength);
    printf("%s\n", ciphertext->cipherV);
    printf("%lu\n", ciphertext->cipherWLength);
    printf("%s\n", ciphertext->cipherW);
}

void readPrivateKeyFromFile(AffinePoint privateKey)
{
    FILE * fp;
    fp = fopen("pk", "rb");
    if (fp != NULL) {

        fread(&privateKey, sizeof(struct AffinePoint), 1, fp);

        fclose(fp);
    }
}

int main()
{
    const char *message = "Ironic.";
    const char *identity = "darth.plagueis@sith.com";

    PublicParameters* publicParameters = malloc(sizeof (PublicParameters));
    mpz_t masterSecret;
    mpz_init(masterSecret);
    mpz_init(publicParameters->q);
    if (CRYPTID_SUCCESS != cryptid_setup(LOWEST, publicParameters, masterSecret))
    {
        printf("Setup failed\n");
        return -1;
    }

    CipherTextTuple* ciphertext = malloc(sizeof (CipherTextTuple));
    if (CRYPTID_SUCCESS != cryptid_encrypt(ciphertext, message, strlen(message), identity, strlen(identity), *publicParameters))
    {
        printf("Encrypt failed\n");
        return -1;
    }


    AffinePoint privateKey;
    if (CRYPTID_SUCCESS != cryptid_extract(&privateKey, identity, strlen(identity), *publicParameters, masterSecret))
    {
        printf("Extract failed\n");
        return -1;
    }

    //Writing parameters to file
    writePublicParToFile(publicParameters);
    writeCipherTextToFile(ciphertext);
    writePrivateKeyToFile(privateKey);



    //Read everything from file
    readCipherTextFromFile(ciphertext);
    readPublicParFromFile(publicParameters);
    readPrivateKeyFromFile(privateKey);

    if(CRYPTID_VALIDATION_SUCCESS != validation_isPublicParametersValid(*publicParameters))
    {
        printf("Public par invalid\n");
        return -1;
    }
    else printf("public par valid\n"); 


    char *plaintext;
    if (CRYPTID_SUCCESS != cryptid_decrypt(&plaintext, privateKey, *ciphertext, *publicParameters))
    {
        printf("Decrypt failed\n");
        return -1;
    }

    printf("Plaintext:\n%s\n", plaintext);
    free(plaintext);
    cipherTextTuple_destroy(*ciphertext);
    free(ciphertext);
    affine_destroy(privateKey);
    mpz_clears(publicParameters->q, masterSecret, NULL);
    affine_destroy(publicParameters->pointP);
    affine_destroy(publicParameters->pointPpublic);
    ellipticCurve_destroy(publicParameters->ellipticCurve);
    free(publicParameters);
    return 0;
}
