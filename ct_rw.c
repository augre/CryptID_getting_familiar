#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gmp.h"

#include "CryptID.h"
#include "util/Validation.h"


void writeCipherTextToFile(CipherTextTuple* ciphertext)
{
    FILE * fp;
    fp = fopen ("CT/cipher","wb");
    if (fp != NULL) {

        //fwrite(&ciphertext->cipherU, sizeof(ciphertext->cipherU), 1, fp);

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

    fp = fopen ("CT/cipherUx","w+");
    if (fp != NULL) {
        mpz_out_str(fp, 10, ciphertext->cipherU.x);
        fclose(fp);
    }
    printf ("  wrote  "); mpz_out_str (stdout, 10, ciphertext->cipherU.x); printf("\n");

    fp = fopen ("CT/cipherUy","w+");
    if (fp != NULL) {
        mpz_out_str(fp, 10, ciphertext->cipherU.y);
        fclose(fp);
    }
    printf ("  wrote  "); mpz_out_str (stdout, 10, ciphertext->cipherU.y); printf("\n");
}

CipherTextTuple readCipherTextFromFile()
{
    CipherTextTuple ciphertext;

    FILE * fp;

    fp = fopen("CT/cipher", "rb");
    if (fp != NULL) {

        //fread(&ciphertext.cipherU, sizeof(ciphertext.cipherU), 1, fp);
        fread(&ciphertext.cipherVLength, sizeof(ciphertext.cipherVLength), 1, fp);

	ciphertext.cipherV = malloc(ciphertext.cipherVLength + 1);
        fread(ciphertext.cipherV, ciphertext.cipherVLength + 1, 1, fp);
        fread(&ciphertext.cipherWLength, sizeof(ciphertext.cipherWLength), 1, fp);

	ciphertext.cipherW = malloc(ciphertext.cipherWLength + 1);
        fread(ciphertext.cipherW, ciphertext.cipherWLength + 1, 1, fp);

        fclose(fp);
    }

    else printf("Can't open file");
    printf("kiolvasott:\n");
    printf("VLength: %lu\n", ciphertext.cipherVLength);
    printf("%s\n", ciphertext.cipherV);
    printf("%lu\n", ciphertext.cipherWLength);
    printf("%s\n", ciphertext.cipherW);

    mpz_t x, y;
    mpz_inits(x, y, NULL);
    fp = fopen ("CT/cipherUx","r");
    if (fp != NULL) {
        mpz_inp_str(x, fp, 10);
        fclose(fp);
    }

    fp = fopen ("CT/cipherUy","r");
    if (fp != NULL) {
        mpz_inp_str(y, fp, 10);
        fclose(fp);
    }

    ciphertext.cipherU = affine_init(x, y);

    printf ("  read in  "); mpz_out_str (stdout, 10, ciphertext.cipherU.x); printf("\n");
    printf ("  read in  "); mpz_out_str (stdout, 10, ciphertext.cipherU.y); printf("\n");
    return ciphertext;
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
    (validation_isCipherTextTupleValid(*ciphertext, publicParameters->ellipticCurve.fieldOrder)) ? (printf("cipher valid\n")) : (printf("cipher invalid\n"));

    writeCipherTextToFile(ciphertext);

    CipherTextTuple ct = readCipherTextFromFile();

    (validation_isAffinePointValid(ct.cipherU, publicParameters->ellipticCurve.fieldOrder)) ? (printf("cipherU aff point valid\n")) : (printf("cipherU aff point invalid\n"));
    (ct.cipherV) ? (printf("cipherV valid\n")) : (printf("cipherV invalid\n"));
//    (ct.cipherVLength != 0)
//    (ct.cipherW)
//    (ct.cipherWLength != 0)


    (validation_isCipherTextTupleValid(ct, publicParameters->ellipticCurve.fieldOrder)) ? (printf("read cipher valid\n")) : (printf("read cipher invalid\n"));
    return 0;
}
